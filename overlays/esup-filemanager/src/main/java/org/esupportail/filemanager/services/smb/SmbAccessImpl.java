/**
 * Licensed to EsupPortail under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * EsupPortail licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.esupportail.filemanager.services.smb;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import jakarta.annotation.Resource;
import org.esupportail.filemanager.beans.CasUser;
import org.esupportail.filemanager.beans.DownloadFile;
import org.esupportail.filemanager.beans.JsTreeFile;
import org.esupportail.filemanager.beans.RoleProperties;
import org.esupportail.filemanager.beans.ShareProperties;
import org.esupportail.filemanager.beans.UploadActionType;
import org.esupportail.filemanager.beans.UserPassword;
import org.esupportail.filemanager.exceptions.EsupStockException;
import org.esupportail.filemanager.exceptions.EsupStockFileExistException;
import org.esupportail.filemanager.exceptions.EsupStockLostSessionException;
import org.esupportail.filemanager.services.FsAccess;
import org.esupportail.filemanager.services.ResourceUtils;
import org.esupportail.filemanager.services.auth.KerberosUserAuthenticatorService;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.FileCopyUtils;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmbAccessImpl extends FsAccess implements DisposableBean {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SmbAccessImpl.class);

    // -----------------------------------------------------------------------
    // SMB connection state
    // -----------------------------------------------------------------------

    private SMBClient smbClient;
    private Connection connection;
    private Session session;
    private DiskShare diskShare;

    /** Parsed from the URI (smb://host[:port]/share[/basePath]) */
    private String smbHost;
    private int smbPort = SMBClient.DEFAULT_PORT;
    private String smbShareName;
    /** Base path inside the share (uses backslash separator, may be empty). */
    private String smbBasePath;


    @Autowired
    RoleProperties roleProperties;

    @Autowired
    ShareProperties shareProperties;

    private String branch;

    public SMBClient getSmbClient() {
        return smbClient;
    }

    public void setSmbClient(SMBClient smbClient) {
        this.smbClient = smbClient;
    }

    /**
     * SMB dialect actually negotiated with the server (e.g. "SMB 3.1.1").
     * Updated each time a connection is established.
     */
    private volatile String negotiatedDialect = "SMB";

    // -----------------------------------------------------------------------
    // Spring wiring
    // -----------------------------------------------------------------------

    @Resource
    private ResourceUtils resourceUtils;

    public void setResourceUtils(ResourceUtils resourceUtils) {
        this.resourceUtils = resourceUtils;
    }


    // -----------------------------------------------------------------------
    // FsAccess overrides
    // -----------------------------------------------------------------------

    @Override
    public String getConnectionType() {
        return negotiatedDialect;
    }

    /**
     * Converts an {@link SMB2Dialect} enum value to a human-readable version string.
     */
    private static String formatSmbDialect(SMB2Dialect dialect) {
        if (dialect == null) return "SMB";
        switch (dialect) {
            case SMB_2_0_2: return "SMB 2.0.2";
            case SMB_2_1:   return "SMB 2.1";
            case SMB_2XX:   return "SMB 2.x";
            case SMB_3_0:   return "SMB 3.0";
            case SMB_3_0_2: return "SMB 3.0.2";
            case SMB_3_1_1: return "SMB 3.1.1";
            default:        return "SMB";
        }
    }

    // -----------------------------------------------------------------------
    // Auth-error detection helpers
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} when the NTSTATUS code signals an authentication or
     * session-level error (expired Kerberos TGT, invalidated SMB session, …).
     * In those cases the connection must be torn down so that the next {@link #open()}
     * call obtains fresh credentials instead of reusing a stale session.
     */
    private static boolean isAuthError(SMBApiException e) {
        NtStatus status = e.getStatus();
        return status == NtStatus.STATUS_ACCESS_DENIED           // 0xC0000022
                || status == NtStatus.STATUS_LOGON_FAILURE           // 0xC000006D
                || status == NtStatus.STATUS_NETWORK_SESSION_EXPIRED // 0xC000035C
                || status == NtStatus.STATUS_USER_SESSION_DELETED;   // 0xC0000203
    }

    /**
     * Wraps an {@link SMBApiException} into an {@link EsupStockException} for rethrowing.
     * When the exception signals an auth/session error the current SMB connection is
     * closed first, so that the next {@link #open()} call (triggered e.g. by
     * {@link FsAccess#authenticate}) establishes
     * a fresh, authenticated connection and obtains a new Kerberos TGT if needed.
     */
    private EsupStockException wrapSmbException(SMBApiException e) {
        if (isAuthError(e)) {
            log.warn("SMB auth/session error on '{}' (status {}) – closing connection to force re-authentication",
                    smbHost, e.getStatus());
            close();
        }
        return new EsupStockException(e);
    }

    // -----------------------------------------------------------------------
    // URI parsing helpers
    // -----------------------------------------------------------------------

    /**
     * Parses the inherited {@link #uri} field into {@link #smbHost},
     * {@link #smbPort}, {@link #smbShareName} and {@link #smbBasePath}.
     * <p>
     * Expected format: {@code smb://hostname[:port]/sharename[/optional/base/path]}
     */
    private void parseUri() {
        String u = uri;
        if (u.startsWith("smb://")) {
            u = u.substring(6);
        }
        // Strip trailing slashes
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }

        int firstSlash = u.indexOf('/');
        String hostPart;
        String rest;
        if (firstSlash < 0) {
            hostPart = u;
            smbShareName = "";
            smbBasePath = "";
        } else {
            hostPart = u.substring(0, firstSlash);
            rest = u.substring(firstSlash + 1);
            int secondSlash = rest.indexOf('/');
            if (secondSlash < 0) {
                smbShareName = rest;
                smbBasePath = "";
            } else {
                smbShareName = rest.substring(0, secondSlash);
                smbBasePath = rest.substring(secondSlash + 1).replace("/", "\\");
            }
        }

        // Separate host and optional port
        int colonIdx = hostPart.lastIndexOf(':');
        if (colonIdx >= 0) {
            smbHost = hostPart.substring(0, colonIdx);
            try {
                smbPort = Integer.parseInt(hostPart.substring(colonIdx + 1));
            } catch (NumberFormatException e) {
                log.warn("Unable to parse SMB port from URI '{}', using default 445", uri);
                smbHost = hostPart;
                smbPort = SMBClient.DEFAULT_PORT;
            }
        } else {
            smbHost = hostPart;
            smbPort = SMBClient.DEFAULT_PORT;
        }
    }

    /**
     * Builds the SMB path (backslash-separated, relative to share root) by
     * combining the base path declared in the URI with the caller-supplied
     * relative path (which may use forward or backslashes).
     */
    private String buildSmbPath(String relativePath) {
        String base = smbBasePath != null ? smbBasePath : "";
        if (relativePath == null || relativePath.isEmpty()) {
            return base;
        }
        String rel = relativePath.replace("/", "\\");
        if (base.isEmpty()) {
            return rel;
        }
        return base + "\\" + rel;
    }

    // -----------------------------------------------------------------------
    // Connection lifecycle
    // -----------------------------------------------------------------------

    @Override
    protected void open() {
        super.open();
        if (!isOpened()) {
            try {
                parseUri();

                if (userAuthenticatorService instanceof KerberosUserAuthenticatorService kerberosAuth) {
                    // ---- Kerberos / SPNEGO path ----
                    // The KerberosUserAuthenticatorService owns all Kerberos config and caches
                    // the JAAS Subject (TGT) for the lifetime of the HTTP session.
                    UserPassword up = kerberosAuth.getUserPassword();
                    String username = up.getUsername() != null ? up.getUsername() : "";
                    String domain   = kerberosAuth.getKerberosRealm() != null ? kerberosAuth.getKerberosRealm() : "";

                    if (username.isEmpty()) {
                        throw new EsupStockLostSessionException("Kerberos authentication skipped: user not yet authenticated");
                    }

                    Subject kerberosSubject = kerberosAuth.getOrObtainKerberosSubject();

                    SmbConfig smbConfig = SmbConfig.builder()
                            .withAuthenticators(new SpnegoAuthenticator.Factory())
                            .build();
                    smbClient = new SMBClient(smbConfig);
                    connection = smbClient.connect(smbHost, smbPort);

                    GSSAuthenticationContext authContext =
                            new GSSAuthenticationContext(username, domain, kerberosSubject, null);
                    session = connection.authenticate(authContext);

                } else {
                    // ---- Classic NTLM path ----
                    smbClient = new SMBClient();
                    connection = smbClient.connect(smbHost, smbPort);

                    AuthenticationContext authContext;
                    if (userAuthenticatorService != null) {
                        UserPassword up = userAuthenticatorService.getUserPassword();
                        String username = up.getUsername() != null ? up.getUsername() : "";
                        char[] password = up.getPassword() != null ? up.getPassword().toCharArray() : new char[0];
                        String domain   = up.getDomain()    != null ? up.getDomain()    : "";
                        authContext = new AuthenticationContext(username, password, domain);
                    } else {
                        authContext = AuthenticationContext.anonymous();
                    }
                    session = connection.authenticate(authContext);
                }

                if (smbShareName != null && !smbShareName.trim().isEmpty() && !"/".equals(smbShareName.trim())) {

                    diskShare = (DiskShare) session.connectShare(smbShareName);
                    // Capture the negotiated SMB dialect (e.g. SMB 3.1.1) for monitoring
                    try {
                        NegotiatedProtocol np = connection.getNegotiatedProtocol();
                        if (np != null) {
                            negotiatedDialect = formatSmbDialect(np.getDialect());
                        }
                    } catch (Exception e) {
                        log.debug("Could not retrieve negotiated SMB dialect", e);
                    }
                    notifyConnectionOpened();
                    log.info("SMB connection opened: {}:{}/{} (kerberos={})",
                            smbHost, smbPort, smbShareName,
                            userAuthenticatorService instanceof KerberosUserAuthenticatorService);
                }else{

                    if(!sharesValidated){
                        validShares = getSharesForRole(getRole());
                    }

                }
            } catch (LoginException e) {
                close(); // clean up any partially-opened resources
                throw new EsupStockException("Kerberos authentication failed: " + e.getMessage(), e);
            } catch (IOException e) {
                close(); // clean up any partially-opened resources
                throw new EsupStockException(e);
            }
        }
    }

    private List<String> getSharesForRole(String userRole) {

        log.debug("Getting shares for role {}", userRole);
        String[] sharesForRole;
        switch (userRole){
            case RoleProperties.ROLE_ELEVE -> sharesForRole = shareProperties.getEleve();
            case RoleProperties.ROLE_PROF -> sharesForRole = shareProperties.getProf();
            case RoleProperties.ROLE_ADMIN -> sharesForRole = shareProperties.getAdmin();
            case RoleProperties.ROLE_AGENT_COLL_TER -> sharesForRole = shareProperties.getAgentcoll();
            default -> throw new RuntimeException("Invalid role");
        }
        log.debug("Returning share(s) : {}", Arrays.toString(sharesForRole));
        sharesForRole = Arrays.stream(sharesForRole).map(x -> x.replace(TOKEN_FORM_USERNAME,userAuthenticatorService.getUserPassword().getUsername())).toArray(String[]::new);
        return Arrays.asList(sharesForRole);
    }

    private String getRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CasUser casUser = (CasUser)authentication.getPrincipal();
        List<String> isMemberOf = (List<String>) casUser.getAttributes().get("isMemberOf");
        String uai = getUai();


        String[] regexesEleve = Arrays.stream(roleProperties.getEleve()).map(x -> x.replace("{UAI}", uai)).toArray(String[]::new);
        String[] regexesProf = Arrays.stream(roleProperties.getProf()).map(x -> x.replace("{UAI}", uai)).toArray(String[]::new);
        String[] regexesAdmin = Arrays.stream(roleProperties.getAdmin()).map(x -> x.replace("{UAI}", uai)).toArray(String[]::new);
        String[] regexesAgent = Arrays.stream(roleProperties.getAgentcoll()).map(x -> x.replace("{UAI}", uai)).toArray(String[]::new);

        if(matchesProfileRegexesWithIsMemberOf(regexesEleve, isMemberOf)){
            return RoleProperties.ROLE_ELEVE;
        }

        if(matchesProfileRegexesWithIsMemberOf(regexesProf, isMemberOf)){
            return RoleProperties.ROLE_PROF;
        }

        if(matchesProfileRegexesWithIsMemberOf(regexesAdmin, isMemberOf)){
            return RoleProperties.ROLE_ADMIN;
        }

        if(matchesProfileRegexesWithIsMemberOf(regexesAgent, isMemberOf)){
            return RoleProperties.ROLE_AGENT_COLL_TER;
        }
       return RoleProperties.ROLE_UNKNOWN;
    }


    private boolean matchesProfileRegexesWithIsMemberOf(String[] regexesProfile, List<String> isMemberOf){

        for(String regexProfile: regexesProfile){
            if(matchesProfileRegexWithIsMemberOf(regexProfile, isMemberOf)){
                return true;
            }
        }
        return false;
    }

    private boolean matchesProfileRegexWithIsMemberOf(String regexProfile, List<String> isMemberOf){
        log.debug("Trying to match {} with {}", regexProfile, isMemberOf.toString());
        Pattern pattern = Pattern.compile(regexProfile);
        for (String isMemberOfLine : isMemberOf) {
            Matcher matcher = pattern.matcher(isMemberOfLine);
            if (matcher.matches()) {
                log.debug("Matched {} with {}", regexProfile, isMemberOfLine);
               return true;
            }
        }
       return false;
    }

    private String getUai(){
        log.debug("Get UAI, regex is {}, trying to match {}", roleProperties.getRegexUai(), this.uri);
        Pattern pattern = Pattern.compile(roleProperties.getRegexUai());
        Matcher matcher = pattern.matcher(this.uri);

        if (matcher.matches()) {
            String firstGroup = matcher.group(1).toUpperCase();
            log.debug("Get UAI found {}", firstGroup);
            return  firstGroup;
        }
        throw new RuntimeException("This drive hostname does not match an UAI regex");
    }

    @Override
    public void close() {
        if (diskShare != null) {
            notifyConnectionClosed();
            try { diskShare.close(); } catch (Exception e) { log.warn("Error closing disk share", e); }
            diskShare = null;
        }
        if (session != null) {
            try { session.close(); } catch (Exception e) { log.warn("Error closing SMB session", e); }
            session = null;
        }
        if (connection != null) {
            try { connection.close(); } catch (Exception e) { log.warn("Error closing SMB connection", e); }
            connection = null;
        }
        if (smbClient != null) {
            try { smbClient.close(); } catch (Exception e) { log.warn("Error closing SMB client", e); }
            smbClient = null;
        }
        if (userAuthenticatorService instanceof KerberosUserAuthenticatorService kerberosAuth) {
            kerberosAuth.invalidateKerberosSubject();
        }
    }

    @Override
    protected boolean isOpened() {
        return diskShare != null && diskShare.isConnected();
    }

    @Override
    public void destroy() throws Exception {
        close();
    }

    // -----------------------------------------------------------------------
    // Directory / file metadata helpers
    // -----------------------------------------------------------------------

    /** Returns {@code true} if the file attribute long has the DIRECTORY bit set. */
    private static boolean isDirectory(long fileAttributes) {
        return (fileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) != 0;
    }

    /** Converts a smbj {@link FileTime} to a {@link Date}, or {@code null} if unset. */
    private static Date toDate(FileTime ft) {
        if (ft == null || ft.getWindowsTimeStamp() == 0) {
            return null;
        }
        long epochMillis = ft.toEpochMillis();
        return epochMillis > 0 ? new Date(epochMillis) : null;
    }

    /**
     * Builds a {@link JsTreeFile} for the entry at {@code smbPath} on the share.
     * When {@code smbPath} is empty the method returns the root ("drive") node.
     */
    private JsTreeFile smbPathAsJsTreeFile(String smbPath, String relativePath,
                                           boolean folderDetails, boolean fileDetails) {
        if (smbPath.isEmpty()) {
            // Root of the configured share/base-path → behave as a "drive" node
            JsTreeFile root = new JsTreeFile("", "", "", "drive");
            if (folderDetails) {
                populateFolderDetails(root, smbPath);
            }
            return root;
        }

        try {

            String sharePart = null;

            if(Objects.nonNull(validShares)){
                String[] smbPathArray = smbPath.split("[/\\\\]",2);

                if(validShares.contains(smbPathArray[0])){
                    sharePart = smbPathArray[0];
                }

                diskShare = (DiskShare) session.connectShare(sharePart);

                assert sharePart != null;
                smbPath =smbPathArray.length > 1 ? smbPathArray[1] : "";
            }


            FileAllInformation info = diskShare.getFileInformation(smbPath);
            boolean dir = isDirectory(info.getBasicInformation().getFileAttributes());
            String type = dir ? "folder" : "file";

            // Title = last path component
            String title = smbPath.contains("\\")
                    ? smbPath.substring(smbPath.lastIndexOf('\\') + 1)
                    : smbPath;

            if(Objects.nonNull(validShares)){

                if(smbPath.contains("\\")){
                    title = smbPath.substring(smbPath.lastIndexOf('\\') + 1);
                }else{
                    if(smbPath.isEmpty()){
                        title = sharePart;
                    }else{
                        title = smbPath;
                    }
                }
            }


            String parentRelPath = relativePath.contains("/")
                    ? relativePath.substring(0, relativePath.lastIndexOf('/'))
                    : "";

            if(Objects.nonNull(validShares)){
                parentRelPath = relativePath.contains("/")
                        ? relativePath.substring(0, relativePath.lastIndexOf('/'))
                        : relativePath;
            }

            JsTreeFile file = new JsTreeFile(title, relativePath, parentRelPath, type);

            if (!dir && resourceUtils != null) {
                file.setIcon(resourceUtils.getIcon(title));
                long size = info.getStandardInformation().getEndOfFile();
                file.setSize(size);
                file.setOverSizeLimit(size > resourceUtils.getSizeLimit(title));
            }

            Date lastModified = toDate(info.getBasicInformation().getLastWriteTime());
            if (lastModified != null) {
                file.setLastModifiedTime(lastModified);
            }

            if (folderDetails && dir) {
                populateFolderDetails(file, smbPath);
            }

            return file;
        } catch (SMBApiException e) {
            throw wrapSmbException(e);
        }
    }

    /** Counts children and total size for a directory node. */
    private void populateFolderDetails(JsTreeFile file, String smbPath) {
        try {
            List<FileIdBothDirectoryInformation> children = diskShare.list(smbPath);
            long totalSize = 0, fileCount = 0, folderCount = 0;
            for (FileIdBothDirectoryInformation child : children) {
                String name = child.getFileName();
                if (".".equals(name) || "..".equals(name)) continue;
                if (isDirectory(child.getFileAttributes())) {
                    folderCount++;
                } else {
                    fileCount++;
                    totalSize += child.getEndOfFile();
                }
            }
            file.setTotalSize(totalSize);
            file.setFileCount(fileCount);
            file.setFolderCount(folderCount);
        } catch (Exception e) {
            log.warn("Error computing folder details for '{}': {}", smbPath, e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // FsAccess abstract methods
    // -----------------------------------------------------------------------

    @Override
    public JsTreeFile get(String path, boolean folderDetails, boolean fileDetails) {
        this.open();
        try {
            return smbPathAsJsTreeFile(buildSmbPath(path), path, folderDetails, fileDetails);
        } catch (SMBApiException e) {
            throw wrapSmbException(e);
        }
    }

    @Override
    public List<JsTreeFile> getChildren(String path) {

        log.info("GETCHILDRENSMB path: {}", path);
        this.open();

        List<JsTreeFile> files = new ArrayList<>();

        try {

            boolean pathNullOrEmpty = Objects.isNull(path) || path.isEmpty();

            if (diskShare == null || ( Objects.nonNull(validShares) && pathNullOrEmpty ) ) {

                //si on a déjà discover, ne pas re requeter
//                if(Objects.isNull(validShares)){
//                    //List<String> shares = discoverShares();
//
//                }

                for (String share : validShares) {


                    if (".".equals(share) || "..".equals(share)) continue;
                    if (share.startsWith(".")) continue;

                    boolean dir = true;

                    String type = dir ? "folder" : "file";

                    String childRelPath =
                            (path == null || path.isEmpty())
                                    ? share
                                    : path + "/" + share;

                    String parentRelPath =
                            path != null ? path : "";

                    JsTreeFile jsFile =
                            new JsTreeFile(share, childRelPath, parentRelPath, type);

                    log.info("GETCHILDRENSMB path response A : parent {}, child {}", parentRelPath, childRelPath);


//                    JsTreeFile jsFile = new JsTreeFile(
//                            share,
//                            share,
//                            "",
//                            "folder"
//                    );

                    files.add(jsFile);
                }

                return files;
            }

            // 🌟 CAS 2 : navigation normale SMB


            String pathPrefix = "";

            if(Objects.nonNull(validShares)){
                String[] smbPathArray = path.split("/",2);

                String sharePart = null;

                if(validShares.contains(smbPathArray[0])){
                    sharePart = smbPathArray[0];
                }

                diskShare = (DiskShare) session.connectShare(sharePart);

                assert sharePart != null;
                path = smbPathArray.length > 1 ? smbPathArray[1] : "";
                pathPrefix = sharePart;
            }


            String smbPath = buildSmbPath(path);

            List<FileIdBothDirectoryInformation> list = diskShare.list(smbPath);

            for (FileIdBothDirectoryInformation entry : list) {

                String name = entry.getFileName();

                if (".".equals(name) || "..".equals(name)) continue;
                if (name.startsWith(".")) continue;

                boolean dir = isDirectory(entry.getFileAttributes());

                String type = dir ? "folder" : "file";

                String childRelPath =
                        (path == null || path.isEmpty())
                                ? name
                                : path + "/" + name;

                String parentRelPath =
                        path != null ? path : "";


                if(!pathPrefix.isEmpty())
                {
                    childRelPath = String.join("/", pathPrefix, childRelPath);
                    parentRelPath = !parentRelPath.isEmpty() ? String.join("/", pathPrefix, parentRelPath) : pathPrefix;
                }


                log.info("GETCHILDRENSMB path response B : parent {}, child {}", parentRelPath, childRelPath);
                JsTreeFile jsFile =
                        new JsTreeFile(name, childRelPath, parentRelPath, type);

                if (!dir && resourceUtils != null) {

                    jsFile.setIcon(resourceUtils.getIcon(name));

                    long size = entry.getEndOfFile();

                    jsFile.setSize(size);

                    jsFile.setOverSizeLimit(
                            size > resourceUtils.getSizeLimit(name)
                    );
                }

                Date lastModified = toDate(entry.getLastWriteTime());

                if (lastModified != null) {
                    jsFile.setLastModifiedTime(lastModified);
                }

                files.add(jsFile);
            }

        } catch (SMBApiException e) {
            throw wrapSmbException(e);
        }

        return files;
    }

    private List<String> getValidShares(List<String> candidates) {

        List<String> valid = new ArrayList<>();

        for (String share : candidates) {

            //replace %form_username%

            if (isShareValid(share)) {
                valid.add(share);
            }
        }
        validShares = valid;
        sharesValidated = true;
        return valid;
    }

    List<String> validShares;
    List<String> shares;

    public List<String> getShares() {
        return shares;
    }

    public void setShares(List<String> shares) {
        this.shares = shares;
    }

    boolean sharesValidated = false;

    private boolean isShareValid(String share) {
        try {
            DiskShare test = (DiskShare) session.connectShare(share);

            // test minimal (beaucoup plus léger que parcourir)
            test.list("");

            test.close();

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private List<String> discoverShares() {

        List<String> shares = new ArrayList<>();

        try {

            UserPassword up = userAuthenticatorService.getUserPassword();

            String user = up.getUsername();
            String domain = up.getDomain();
            String password = up.getPassword();

            List<String> cmd = new ArrayList<>();

            cmd.add("smbclient");
            cmd.add("-L");
            cmd.add("//" + smbHost);

            cmd.add("-U");
            cmd.add(user + "%" + password);

            if (domain != null && !domain.isEmpty()) {
                cmd.add("-W");
                cmd.add(domain);
            }

            cmd.add("-m");
            cmd.add("SMB2");

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);

            log.info("SMB CLIENT CMD {}", cmd);
            Process p = pb.start();

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(p.getInputStream()))) {

                String line;
                boolean inShares = false;

                while ((line = reader.readLine()) != null) {

                    line = line.trim();

                    if (line.contains("Sharename")) {
                        inShares = true;
                        continue;
                    }

                    if (!inShares) continue;

                    if (line.isEmpty()) continue;

                    if (line.startsWith("-") ||
                            line.startsWith("IPC$") ||
                            line.startsWith("Sharename")) {
                        continue;
                    }

                    String[] parts = line.split("\\s+");
                    if (parts.length > 0) {
                        String share = parts[0];

                        if (!share.endsWith("$")) {
                            shares.add(share);
                        }
                    }
                }
            }

            p.waitFor();

        } catch (Exception e) {
            log.warn("SMB share discovery failed for {}: {}", smbHost, e.getMessage());
        }

        return shares;
    }




    @Override
    public boolean remove(String path) {


        if(Objects.nonNull(validShares)){
            String[] smbPathArray = path.split("/",2);

            String sharePart = null;

            if(validShares.contains(smbPathArray[0])){
                sharePart = smbPathArray[0];
            }

            diskShare = (DiskShare) session.connectShare(sharePart);

            assert sharePart != null;
            path = smbPathArray.length > 1 ? smbPathArray[1] : "";
        }


        this.open();
        try {




            String smbPath = buildSmbPath(path);
            if (diskShare.folderExists(smbPath)) {
                diskShare.rmdir(smbPath, true);
            } else {
                diskShare.rm(smbPath);
            }
            log.debug("Removed SMB entry '{}'", path);
            return true;
        } catch (Exception e) {
            log.warn("Cannot remove '{}': {}", path, e.getMessage());
            return false;
        }
    }

    @Override
    public String createFile(String parentPath, String title, String type) {
        this.open();
        try {
//         String smbPath = buildSmbPath(parentPath);
            if(Objects.nonNull(validShares)){
                String[] pathArray = parentPath.split("/",2);
                if(validShares.contains(pathArray[0])){
                    if(pathArray.length > 1){
                        parentPath = pathArray[1];
                    }
                }
            }

            String parentSmbPath = buildSmbPath(parentPath);
            String newSmbPath = parentSmbPath.isEmpty() ? title : parentSmbPath + "\\" + title;
            String newRelPath = (parentPath == null || parentPath.isEmpty()) ? title : parentPath + "/" + title;

            if ("folder".equals(type)) {
                diskShare.mkdir(newSmbPath);
                log.info("SMB folder '{}' created", title);
            } else {
                try (com.hierynomus.smbj.share.File f = diskShare.openFile(
                        newSmbPath,
                        EnumSet.of(AccessMask.GENERIC_WRITE),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                        EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE),
                        SMB2CreateDisposition.FILE_CREATE,
                        null)) {
                    // empty file created on close
                }
                log.info("SMB file '{}' created", title);
            }
            return newRelPath;
        } catch (Exception e) {
            log.warn("Cannot create '{}': {}", title, e.getMessage());
            return null;
        }
    }

    @Override
    public boolean renameFile(String path, String title) {
        this.open();
        try {


            if(Objects.nonNull(validShares)){
                String[] pathArray = path.split("/",2);
                if(validShares.contains(pathArray[0])){
                    if(pathArray.length > 1){
                        path = pathArray[1];
                    }
                }
            }


            String smbPath = buildSmbPath(path);
            String parentSmbPath = smbPath.contains("\\")
                    ? smbPath.substring(0, smbPath.lastIndexOf('\\'))
                    : "";
            String newSmbPath = parentSmbPath.isEmpty() ? title : parentSmbPath + "\\" + title;

            EnumSet<AccessMask> accessMask = EnumSet.of(AccessMask.GENERIC_ALL);
            EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(
                    SMB2ShareAccess.FILE_SHARE_DELETE,
                    SMB2ShareAccess.FILE_SHARE_READ,
                    SMB2ShareAccess.FILE_SHARE_WRITE);

            if (diskShare.folderExists(smbPath)) {
                try (Directory dir = diskShare.openDirectory(
                        smbPath, accessMask, null, shareAccess,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    dir.rename(newSmbPath);
                }
            } else {
                try (com.hierynomus.smbj.share.File file = diskShare.openFile(
                        smbPath, accessMask, null, shareAccess,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    file.rename(newSmbPath);
                }
            }
            log.debug("Renamed SMB '{}' -> '{}'", path, title);
            return true;
        } catch (Exception e) {
            log.warn("Cannot rename '{}' to '{}': {}", path, title, e.getMessage());
            return false;
        }
    }

    @Override
    public boolean moveCopyFilesIntoDirectory(String dir, List<String> filesToCopy, boolean copy) {

        String dirSmbPath = buildSmbPath(dir);

// INVERSER BACKSLASH VERS SLASH
        if(Objects.nonNull(validShares)) {

            String[] dirPathArray = dirSmbPath.split("\\\\", 2);
            if (validShares.contains(dirPathArray[0])) {

                if (dirPathArray.length > 1) {

                    dirSmbPath = dirPathArray[1];
                } else {
                    dirSmbPath = "";
                }

                diskShare = (DiskShare) session.connectShare(dirPathArray[0]);


                List<String> filesPathTemp = new ArrayList<>();
                for (String srcRelPath : filesToCopy) {
                    String[] srcPathArray = srcRelPath.split("/", 2);
                    if (srcPathArray.length > 1) {
                        filesPathTemp.add(srcPathArray[1]);
                    } else {
                        filesPathTemp.add("");
                    }
                }
                filesToCopy = filesPathTemp;

            }
        }

        this.open();
        try {


            for (String srcRelPath : filesToCopy) {
                String srcSmbPath = buildSmbPath(srcRelPath);
                String name = srcSmbPath.contains("\\")
                        ? srcSmbPath.substring(srcSmbPath.lastIndexOf('\\') + 1)
                        : srcSmbPath;
                String destSmbPath = dirSmbPath.isEmpty() ? name : dirSmbPath + "\\" + name;

                if (copy) {
                    copySmbEntry(srcSmbPath, destSmbPath);
                } else {
                    // Move = rename to destination
                    EnumSet<AccessMask> accessMask = EnumSet.of(AccessMask.GENERIC_ALL);
                    EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(
                            SMB2ShareAccess.FILE_SHARE_DELETE,
                            SMB2ShareAccess.FILE_SHARE_READ,
                            SMB2ShareAccess.FILE_SHARE_WRITE);

                    if (diskShare.folderExists(srcSmbPath)) {
                        try (Directory d = diskShare.openDirectory(
                                srcSmbPath, accessMask, null, shareAccess,
                                SMB2CreateDisposition.FILE_OPEN, null)) {
                            d.rename(destSmbPath);
                        }
                    } else {
                        try (com.hierynomus.smbj.share.File f = diskShare.openFile(
                                srcSmbPath, accessMask, null, shareAccess,
                                SMB2CreateDisposition.FILE_OPEN, null)) {
                            f.rename(destSmbPath);
                        }
                    }
                }
            }
            return true;
        } catch (Exception e) {
            log.warn("Cannot move/copy files into '{}': {}", dir, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Recursively copies an SMB entry (file or folder) to a new path on the same share.
     */
    private void copySmbEntry(String srcPath, String destPath) throws IOException {

        String srcPathPrefix;
        if(Objects.nonNull(validShares)){
            String[] srcPathArray = srcPath.split("\\\\",2);
            String[] destPathArray = destPath.split("\\\\",2);

            String sharePart = null;

            if(validShares.contains(srcPathArray[0])){
                sharePart = srcPathArray[0];
                diskShare = (DiskShare) session.connectShare(sharePart);
                srcPath = srcPathArray.length > 1 ? srcPathArray[1] : srcPath;
                destPath = destPathArray.length > 1 ? destPathArray[1] : destPath;
            }
        }


        if (diskShare.folderExists(srcPath)) {
            diskShare.mkdir(destPath);
            List<FileIdBothDirectoryInformation> children = diskShare.list(srcPath);
            for (FileIdBothDirectoryInformation child : children) {
                String name = child.getFileName();
                if (".".equals(name) || "..".equals(name)) continue;
                copySmbEntry(srcPath + "\\" + name, destPath + "\\" + name);
            }
        } else {
            EnumSet<AccessMask> readAccess = EnumSet.of(AccessMask.GENERIC_READ);
            EnumSet<AccessMask> writeAccess = EnumSet.of(AccessMask.GENERIC_WRITE);
            EnumSet<SMB2ShareAccess> shareAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ);

            com.hierynomus.smbj.share.File src = diskShare.openFile(
                    srcPath, readAccess, null, shareAccess,
                    SMB2CreateDisposition.FILE_OPEN, null);
            com.hierynomus.smbj.share.File dest = diskShare.openFile(
                    destPath, writeAccess,
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    shareAccess,
                    SMB2CreateDisposition.FILE_CREATE, null);
            try {
                FileCopyUtils.copy(src.getInputStream(), dest.getOutputStream());
            } finally {
                try { dest.close(); } catch (Exception ignored) { }
                try { src.close(); } catch (Exception ignored) { }
            }
        }
    }

    @Override
    public DownloadFile getFile(String dir) {
        this.open();
        try {
            String smbPath = buildSmbPath(dir);

            if(Objects.nonNull(validShares)){

                String[] pathArray = smbPath.split("\\\\",2);
                if(validShares.contains(pathArray[0])){

                    if(pathArray.length > 1){

                        smbPath = pathArray[1];
                    }
                    else {
                        smbPath = "";
                    }

                }

            }
            String baseName = smbPath.contains("\\")
                    ? smbPath.substring(smbPath.lastIndexOf('\\') + 1)
                    : smbPath;
            String contentType = JsTreeFile.getMimeType(baseName.toLowerCase());

            // Keep the File open – wrap InputStream so the File is closed when the stream is closed
            com.hierynomus.smbj.share.File smbFile = diskShare.openFile(
                    smbPath,
                    EnumSet.of(AccessMask.GENERIC_READ),
                    null,
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE),
                    SMB2CreateDisposition.FILE_OPEN,
                    null);

            long size = smbFile.getFileInformation(FileAllInformation.class)
                    .getStandardInformation().getEndOfFile();
            InputStream inputStream = new SmbFileInputStream(smbFile);
            return new DownloadFile(contentType, size, baseName, inputStream);
        } catch (Exception e) {
            log.warn("Cannot download file '{}': {}", dir, e.getMessage());
            return null;
        }
    }

    @Override
    public boolean putFile(String dir, String filename, InputStream inputStream, UploadActionType uploadOption) {
        this.open();
        boolean success = false;
        String destSmbPath = null;

        try {
            String dirSmbPath = buildSmbPath(dir);

            String pathPrefix = "";

            if(Objects.nonNull(validShares)){
                String[] smbPathArray = dirSmbPath.split("\\\\",2);

                String sharePart = null;

                if(validShares.contains(smbPathArray[0])){
                    sharePart = smbPathArray[0];
                }

                diskShare = (DiskShare) session.connectShare(sharePart);

                assert sharePart != null;
                dirSmbPath = smbPathArray.length > 1 ? smbPathArray[1] : "";
                pathPrefix = sharePart;
            }


            destSmbPath = dirSmbPath.isEmpty() ? filename : dirSmbPath + "\\" + filename;

            if (diskShare.fileExists(destSmbPath)) {
                switch (uploadOption) {
                    case ERROR:
                        throw new EsupStockFileExistException();
                    case OVERRIDE:
                        diskShare.rm(destSmbPath);
                        break;
                    case RENAME_NEW:
                        String newName = getUniqueFilename(filename, "-new-");
                        destSmbPath = dirSmbPath.isEmpty() ? newName : dirSmbPath + "\\" + newName;
                        break;
                    case RENAME_OLD:
                        String oldName = getUniqueFilename(filename, "-old-");
                        String oldDestPath = dirSmbPath.isEmpty() ? oldName : dirSmbPath + "\\" + oldName;
                        try (com.hierynomus.smbj.share.File oldFile = diskShare.openFile(
                                destSmbPath,
                                EnumSet.of(AccessMask.GENERIC_ALL),
                                null,
                                EnumSet.of(SMB2ShareAccess.FILE_SHARE_DELETE,
                                        SMB2ShareAccess.FILE_SHARE_READ,
                                        SMB2ShareAccess.FILE_SHARE_WRITE),
                                SMB2CreateDisposition.FILE_OPEN,
                                null)) {
                            oldFile.rename(oldDestPath);
                        }
                        break;
                }
            }

            try (com.hierynomus.smbj.share.File newFile = diskShare.openFile(
                    destSmbPath,
                    EnumSet.of(AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                    SMB2CreateDisposition.FILE_CREATE,
                    null)) {
                try (OutputStream out = newFile.getOutputStream()) {
                    FileCopyUtils.copy(inputStream, out);
                }
            }
            success = true;

        } catch (EsupStockFileExistException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Cannot upload file '{}': {}", filename, e.getMessage(), e);
        }

        if (!success && destSmbPath != null) {
            try {
                if (diskShare != null && diskShare.fileExists(destSmbPath)) {
                    diskShare.rm(destSmbPath);
                    log.debug("Deleted corrupted upload '{}'", destSmbPath);
                }
            } catch (Exception e) {
                log.debug("Cannot delete corrupted upload '{}': {}", destSmbPath, e.getMessage());
            }
        }

        return success;
    }

    // -----------------------------------------------------------------------
    // Inner helper – keeps the smbj File handle alive while the stream is read
    // -----------------------------------------------------------------------

    /**
     * Wraps the {@link InputStream} returned by a smbj {@link com.hierynomus.smbj.share.File}
     * and closes the underlying File handle when the stream itself is closed.
     */
    private static final class SmbFileInputStream extends InputStream {

        private final com.hierynomus.smbj.share.File smbFile;
        private final InputStream delegate;

        SmbFileInputStream(com.hierynomus.smbj.share.File smbFile) {
            this.smbFile = smbFile;
            this.delegate = smbFile.getInputStream();
        }

        @Override public int read() throws IOException { return delegate.read(); }
        @Override public int read(byte[] b, int off, int len) throws IOException { return delegate.read(b, off, len); }
        @Override public int available() throws IOException { return delegate.available(); }

        @Override
        public void close() throws IOException {
            try {
                delegate.close();
            } finally {
                try { smbFile.close(); } catch (Exception ignored) { }
            }
        }
    }


    @Override
    public boolean isDiscoverableHost(){
        return Objects.nonNull(validShares);
    }


}
