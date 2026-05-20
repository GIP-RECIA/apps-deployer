package org.esupportail.filemanager.beans;

import org.apereo.cas.client.session.HashMapBackedSessionMappingStorage;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "is")
public class RoleProperties {

    String[] eleve;
    String[] prof;
    String[] admin;
    String[] agentcoll;


      public  static final String ROLE_ELEVE = "ELEVE";
      public  static final String ROLE_PROF = "PROF";
      public  static final String ROLE_ADMIN = "ADMIN";
      public  static final String ROLE_AGENT_COLL_TER = "AGENT_COLL_TER";
      public static final String ROLE_UNKNOWN = "UNKNOWN";

    String regexUai;

    public String getRegexUai() {
        return regexUai;
    }

    public void setRegexUai(String regexUai) {
        this.regexUai = regexUai;
    }

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
