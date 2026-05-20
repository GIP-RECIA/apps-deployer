package org.esupportail.filemanager.beans;

import jakarta.annotation.PostConstruct;
import org.esupportail.filemanager.services.auth.DynamicRedirectStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Component
@ConfigurationProperties(prefix = "share")
public class ShareProperties {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DynamicRedirectStrategy.class);


    String[] eleve;

    String[] prof;

    String[] admin;

    String[] agentcoll;

    public String[] getEleve() {
        return eleve;
    }

    public void setEleve(String[] eleve) {
        this.eleve = eleve;
    }

    public String[] getProf() {
        return prof;
    }

    public void setProf(String[] prof) {
        this.prof = prof;
    }

    public String[] getAdmin() {
        return admin;
    }

    public void setAdmin(String[] admin) {
        this.admin = admin;
    }

    public String[] getAgentcoll() {
        return agentcoll;
    }

    public void setAgentcoll(String[] agentcoll) {
        this.agentcoll = agentcoll;
    }
}
