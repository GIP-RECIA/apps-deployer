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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSessionBindingEvent;
import org.apereo.cas.client.session.SingleSignOutFilter;
import org.apereo.cas.client.session.SingleSignOutHttpSessionListener;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.apereo.cas.client.validation.TicketValidator;

import org.esupportail.filemanager.beans.CasProperties;
import org.esupportail.filemanager.services.auth.DynamicRedirectStrategy;
import org.esupportail.filemanager.services.auth.DynamicServiceAuthenticationDetails;
import org.esupportail.filemanager.services.auth.CasUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;
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
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix="cas")
@EnableWebSecurity
public class CasConfig {

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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CasAuthenticationFilter casAuthenticationFilter) throws Exception {

        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieName("XSRF-TOKEN");

        http
                .exceptionHandling()
                .authenticationEntryPoint(casAuthenticationEntryPoint())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl(getUrl() + "/logout?service=" + getService())
                )
                .addFilter(casAuthenticationFilter)
                .csrf(csrf -> csrf.csrfTokenRepository(cookieCsrfTokenRepository));
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
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    @EventListener
    public SingleSignOutHttpSessionListener singleSignOutHttpSessionListener(HttpSessionBindingEvent event) {
        return new SingleSignOutHttpSessionListener();
    }
}
