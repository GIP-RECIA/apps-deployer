package org.esupportail.publisher.aop.notification.configuration;

import fr.recia.notifications.event_rest_client_kafka.HttpNotificationClient;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Data
@ConfigurationProperties(prefix="notification-conf")
@Configuration
public class NotificationAspectConfig {
    private String urlPublicationContenus;
    private String serviceNamePublicationContenus;
    private String apiKeyPublicationContenus;
    private String urlNews;
    private String serviceNameNews;
    private String apiKeyNews;
    private String urlDocuments;
    private String serviceNameDocuments;
    private String apiKeyDocuments;
    private String titleModeration;
    private String linkModeration;
    private String titleNews;
    private String linkNews;
    private String titleDoc;
    private String linkDoc;

    @Bean
    public HttpNotificationClient notificationClientModeration() {
        return new HttpNotificationClient(urlPublicationContenus, serviceNamePublicationContenus, apiKeyPublicationContenus);
    }

    @Bean HttpNotificationClient notificationClientNews() {
        return new HttpNotificationClient(urlNews, serviceNameNews, apiKeyNews);
    }

    @Bean HttpNotificationClient notificationClientDoc() {
        return new HttpNotificationClient(urlDocuments, serviceNameDocuments, apiKeyDocuments);
    }
}
