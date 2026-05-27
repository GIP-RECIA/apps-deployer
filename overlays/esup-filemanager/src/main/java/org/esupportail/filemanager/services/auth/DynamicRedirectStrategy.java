package org.esupportail.filemanager.services.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

public class DynamicRedirectStrategy implements RedirectStrategy {


    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DynamicRedirectStrategy.class);


    public DynamicRedirectStrategy(String []allowedHosts){
        this.allowedHosts = allowedHosts;
    }

    final String[] allowedHosts;



    @Override
    public void sendRedirect(HttpServletRequest request,
                             HttpServletResponse response,
                             String url) throws IOException {

        String dynamicService = buildServiceUrl(request);

        String updatedUrl = updateServiceParameter(url, dynamicService);

        response.sendRedirect(updatedUrl);
    }

    private String updateServiceParameter(String url, String service) {
        String encodedService = URLEncoder.encode(service, StandardCharsets.UTF_8);

        if (url.contains("service=")) {
            return url.replaceAll("service=[^&]*", "service=" + encodedService);
        } else {
            return url + (url.contains("?") ? "&" : "?") + "service=" + encodedService;
        }
    }

    private String buildServiceUrl(HttpServletRequest request) throws UnknownHostException {
        String hostWithScheme = getHostWithScheme(request);

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