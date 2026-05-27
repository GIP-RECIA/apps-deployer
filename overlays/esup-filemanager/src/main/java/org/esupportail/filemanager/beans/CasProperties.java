package org.esupportail.filemanager.beans;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "cas")
public class CasProperties {

    private String url;
    private String service;
    private String key;
    private String[] allowedHosts;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String[] getAllowedHosts() {
        return allowedHosts;
    }

    public void setAllowedHosts(String[] allowedHosts) {
        this.allowedHosts = allowedHosts;
    }
}