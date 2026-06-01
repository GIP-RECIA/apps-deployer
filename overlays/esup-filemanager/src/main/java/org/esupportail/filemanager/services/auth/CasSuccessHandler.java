/**
 * Copyright © 2025 GIP-RECIA (https://www.recia.fr/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.esupportail.filemanager.services.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler simplifié pour le succès d'authentification CAS.
 * Répond en JSON pour les appels API, sinon redirige l'utilisateur.
 */
@Component
public class CasSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {


    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CasSuccessHandler.class);


    @Autowired
    private CustomSessionMappingStorage redisService;

    @Autowired
    private ServletContext servletContext;

    @PostConstruct
    void init(){
        this.setAlwaysUseDefaultTargetUrl(false);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("Authentification terminé avec succés Utilisateur authentifié : {}", authentication.getName());

        // URI et type de requête
        String uri = request.getRequestURI();
        String accept = request.getHeader("Accept");

        log.debug("URI de la requête : {}", uri);
        log.debug("Header Accept : {}", accept != null ? accept : "null");

        // Log tous les headers de la requête
        log.trace("===== Headers de la requête [CAS SH] =====");
        var headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                String headerValue = request.getHeader(headerName);
                log.trace("[CAS SH] {}: {}", headerName, headerValue);
            }
        }
        log.trace("===== Fin des headers de la requête [CAS SH] =====");

        // Log des headers de réponse
            log.trace("===== Headers de la réponse [CAS SH] =====");
        for (String headerName : response.getHeaderNames()) {
            String headerValue = response.getHeader(headerName);
                log.trace("[CAS SH] {}: {}", headerName, headerValue);
        }
            log.trace("===== Fin des headers de la réponse [CAS SH] =====");

        // Authentification et session
            log.debug("Utilisateur authentifié : {}", authentication.getName());
        String credentials = (String) authentication.getCredentials();
            log.debug("Credentials (Session Ticket) : {}", credentials);
        String sessionId = request.getSession(false).getId();
            log.debug("Session ID : {}", sessionId);

        if (credentials == null) {
            throw new RuntimeException("Ticket perdu pour la session: " + sessionId);
        }
        log.debug("Création du mappage entre le ticket [{}] et l'ID de session [{}] dans le cache Redis", credentials, sessionId);
        redisService.setSessionTicketSessionIdPair(credentials, sessionId);

        // Hard coded redirection no longer required?
//        String serverName = request.getServerName();
//        int serverPort = request.getServerPort();
//        String baseUrl = "https://" + serverName + (serverPort == 80 || serverPort == 443 ? "" : ":" + serverPort);
//        getRedirectStrategy().sendRedirect(request, response, baseUrl + servletContext.getContextPath()+"/api/email/summary");
        super.onAuthenticationSuccess(request, response, authentication);
    }



}
