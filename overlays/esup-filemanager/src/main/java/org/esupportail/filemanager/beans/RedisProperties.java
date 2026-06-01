package org.esupportail.filemanager.beans;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "redis")
public class RedisProperties {

    private String hostName;

    private int port;

    private String userName;

    private String password;

    private int databaseIndex;

    private String mappingPrefix;

    private String reverseMappingPrefix;

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getDatabaseIndex() {
        return databaseIndex;
    }

    public void setDatabaseIndex(int databaseIndex) {
        this.databaseIndex = databaseIndex;
    }

    public String getMappingPrefix() {
        return mappingPrefix;
    }

    public void setMappingPrefix(String mappingPrefix) {
        this.mappingPrefix = mappingPrefix;
    }

    public String getReverseMappingPrefix() {
        return reverseMappingPrefix;
    }

    public void setReverseMappingPrefix(String reverseMappingPrefix) {
        this.reverseMappingPrefix = reverseMappingPrefix;
    }

}
