package org.esupportail.filemanager.services.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Optional;

public class DynamicServiceAuthenticationDetails implements ServiceAuthenticationDetails {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DynamicServiceAuthenticationDetails.class);


    private final HttpServletRequest request;
    private final String[] allowedHosts;

    public DynamicServiceAuthenticationDetails(HttpServletRequest request, String[] allowedHosts) {
        this.request = request;
        this.allowedHosts = allowedHosts;
    }

    @Override
    public String getServiceUrl() {
        String hostWithScheme = null;
        try {
            hostWithScheme = getHostWithScheme(request);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

        String contextPath = request.getContextPath();


        return hostWithScheme +
                contextPath +
                "/login/cas";
    }

    private String getHostWithScheme(HttpServletRequest request) throws UnknownHostException {
        String host = getRootDomainUrl(request);


        log.debug("allowedHost {} {}", allowedHosts, host);

        Optional<String> matchedHost =  Arrays.stream(allowedHosts).filter(x -> x.equals(host)).findAny();

        if(matchedHost.isPresent()){
            return host;
        }else{
            throw new UnknownHostException();
        }
    }

    public String getRootDomainUrl(final HttpServletRequest request) {

        final String url = request.getRequestURL().toString();
        final String uri = request.getRequestURI();
        return url.substring(0, url.length() - uri.length());
    }
}