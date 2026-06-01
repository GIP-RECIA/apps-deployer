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
package org.esupportail.filemanager.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apereo.cas.client.session.SingleSignOutFilter;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.apereo.cas.client.validation.TicketValidator;

import org.esupportail.filemanager.beans.CasProperties;
import org.esupportail.filemanager.services.auth.CasSuccessHandler;
import org.esupportail.filemanager.services.auth.CustomSessionMappingStorage;
import org.esupportail.filemanager.services.auth.DynamicRedirectStrategy;
import org.esupportail.filemanager.services.auth.DynamicServiceAuthenticationDetails;
import org.esupportail.filemanager.services.auth.CasUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.ServiceAuthenticationDetails;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

@Configuration
@ConfigurationProperties(prefix="cas")
@EnableWebSecurity
public class CasConfig {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DynamicRedirectStrategy.class);

    @Autowired
    CasProperties casProperties;

    public String getUrl() {
        return casProperties.getUrl();
    }

    public String getService() {
        return casProperties.getService();
    }

    public String getKey() {
        return casProperties.getKey();
    }

    public String[] getAllowedHosts() {
        return casProperties.getAllowedHosts();
    }

    public void setUrl(String url) {
        this.casProperties.setUrl(url);
    }

    public void setService(String service) {
        this.casProperties.setService(service);
    }

    public void setKey(String key) {
        this.casProperties.setKey(key);
    }

    public void setAllowedHosts(String[] allowedHosts){ this.casProperties.setAllowedHosts(allowedHosts);}

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(getService() + "/login/cas");
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }



    @Bean
    @Primary
    public RedirectStrategy redirectStrategy(){
        return new DynamicRedirectStrategy(getAllowedHosts());
    }


    @Bean
    @Primary
    public AuthenticationEntryPoint authenticationEntryPoint(ServiceProperties sP) {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl(getUrl() + "/login");
        entryPoint.setServiceProperties(sP);
        entryPoint.setRedirectStrategy(redirectStrategy());
        return entryPoint;
    }

    @Bean
    public TicketValidator ticketValidator() {
        ;return new Cas20ServiceTicketValidator(getUrl());
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider(ServiceProperties serviceProperties, TicketValidator ticketValidator) {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties);
        provider.setTicketValidator(ticketValidator);
        provider.setAuthenticationUserDetailsService(new CasUserDetailsService());
        provider.setKey(getKey());
        return provider;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
        ep.setLoginUrl(getUrl() + "/login");
        ep.setServiceProperties(serviceProperties());
        ep.setRedirectStrategy(redirectStrategy());
        return ep;
    }


  /*  2026-06-01 12:15:47.534 TRACE [catalina-exec-684] org.springframework.security.web.FilterChainProxy: Invoking DisableEncodeUrlFilter (1/13)
2026-06-01 12:15:47.534 TRACE [catalina-exec-684] org.springframework.security.web.FilterChainProxy: Invoking WebAsyncManagerIntegrationFilter (2/13)
ENTRE CES DEUX FILTRES

2026-06-01 12:15:47.534 TRACE [catalina-exec-684] org.springframework.security.web.FilterChainProxy: Invoking SecurityContextHolderFilter (3/13)
*/



    @Bean
    Filter removeSessionIfSessionNoLongerExistInMappingFilter() {
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    FilterChain filterChain
            ) throws ServletException, IOException {

                HttpSession session = request.getSession(false);

                if (Objects.nonNull(session)) {
                    String sessionId = session.getId();
                    log.info("SESSION NON NULL");

                    if (!ticketSessionMappingStorage.hasSessionId(sessionId)) {

                        log.info("MAPPING NON HAS SESSION ID");

                        // 1. vider auth Spring Security
                        SecurityContextHolder.clearContext();

                        // 2. invalider session proprement
                        session.invalidate();
                    }else{
                        log.info("MAPPING HAS SESSION ID");

                    }
                }

                if(Objects.isNull(session)){
                    log.info("SESSION IS NULL");
                }

                filterChain.doFilter(request, response);
            }
        };

        filter.setBeanName("RemoveSessionIfSessionNoLongerExistInMappingFilter");
        return filter;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CasAuthenticationFilter casAuthenticationFilter) throws Exception {

        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieName("XSRF-TOKEN");

        http
                .exceptionHandling()
                .authenticationEntryPoint(casAuthenticationEntryPoint())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/login/cas**")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/login/cas**")
                        .permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl(getUrl() + "/logout?service=" + getService())
                )
                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
                .addFilter(casAuthenticationFilter)
                .addFilterAfter(removeSessionIfSessionNoLongerExistInMappingFilter(), SecurityContextHolderFilter.class)
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieCsrfTokenRepository)
                        .ignoringRequestMatchers("/login/cas**")
                )
        ;
        return http.build();
    }

    @Bean
    public AuthenticationDetailsSource<HttpServletRequest, ServiceAuthenticationDetails> authenticationDetailsSource() {
        return request -> new DynamicServiceAuthenticationDetails(request, getAllowedHosts());
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationDetailsSource(authenticationDetailsSource());
        filter.setAuthenticationSuccessHandler(casSuccessHandler);
        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager(CasAuthenticationProvider casAuthenticationProvider) {
        return new ProviderManager(List.of(casAuthenticationProvider));
    }


    @Bean
    public SecurityContextLogoutHandler securityContextLogoutHandler() {
        return new SecurityContextLogoutHandler();
    }

    @Bean
    public LogoutFilter logoutFilter(SecurityContextLogoutHandler securityContextLogoutHandler) {
        LogoutFilter logoutFilter = new LogoutFilter(
                getUrl() + "/logout?service=" + getService(), securityContextLogoutHandler);
        logoutFilter.setFilterProcessesUrl("/logout");
        return logoutFilter;
    }

    @Bean
    public Filter singleSignOutFilter() {

        SingleSignOutFilter delegate = new SingleSignOutFilter();
        delegate.setIgnoreInitConfiguration(true);
        delegate.setArtifactParameterName("ticket");
        delegate.setLogoutParameterName("logoutRequest");

        return new OncePerRequestFilter() {

            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain)
                    throws ServletException, IOException {

                String logoutRequest = request.getParameter("logoutRequest");
                String ip = request.getRemoteAddr();
                String uri = request.getRequestURI();
                String method = request.getMethod();

                log.debug("[SLO] Requête entrante : {} {} depuis IP={}", method, uri, ip);

                if (logoutRequest != null) {

                    log.trace("[SLO] URI appelée : {}", uri);
                    log.trace("[SLO] Adresse IP appelante : {}", ip);
                    log.trace("[SLO] XML logoutRequest brut :\n{}", logoutRequest);

                    try {

                        var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
                        var builder = factory.newDocumentBuilder();

                        var doc = builder.parse(
                                new org.xml.sax.InputSource(
                                        new java.io.StringReader(logoutRequest)));

                        doc.getDocumentElement().normalize();

                        var nameIdNode =
                                doc.getElementsByTagName("saml:NameID").item(0);

                        var sessionIndexNode =
                                doc.getElementsByTagName("samlp:SessionIndex").item(0);

                        String nameId =
                                nameIdNode != null
                                        ? nameIdNode.getTextContent()
                                        : "inconnu";

                        String ticket =
                                sessionIndexNode != null
                                        ? sessionIndexNode.getTextContent()
                                        : "inconnu";

                        boolean isSessionTicket = ticket.startsWith("ST-");

                        if (isSessionTicket) {

                            log.debug(
                                    "[SLO] Ticket Invalidation Request will be handled: {}",
                                    ticket);

//                            log.info("getID_TO_SESSION_KEY_MAPPING {}", ticketSessionMappingStorage.getID_TO_SESSION_KEY_MAPPING().entrySet().toString());
//                            log.info("getMANAGED_SESSIONS {}", ticketSessionMappingStorage.getMANAGED_SESSIONS().entrySet().toString());
                            String sessionId = ticketSessionMappingStorage.getSessionIdFromSessionTicket(ticket);

                            ticketSessionMappingStorage.removeSessionTicket(ticket);

                            log.debug("[SLO] Utilisateur CAS (NameID) : {}", nameId);


                        } else {

                            log.debug(
                                    "[SLO] Ticket Invalidation Request ignored: {}",
                                    ticket);
                        }

                    } catch (Exception e) {

                        log.error(
                                "[SLO] Erreur de parsing XML logoutRequest",
                                e);
                    }
                }
                else {

//                    String ticket = request.getParameter("ticket");
//
//                    if (ticket != null) {
//
//                        HttpSession session = request.getSession(false);
//
//                        if (session != null) {
//
//                            ticketSessionMappingStorage.addSessionById(
//                                    ticket,
//                                    session);
//
//                            log.debug(
//                                    "[SLO] Mapping ajouté ticket [{}] -> session [{}]",
//                                    ticket,
//                                    session.getId());
//                        }
//                    }

                    filterChain.doFilter(request, response);
                }
            }
        };
    }

    @Autowired
    private CasSuccessHandler casSuccessHandler;

    @Autowired
    CustomSessionMappingStorage ticketSessionMappingStorage;
}
