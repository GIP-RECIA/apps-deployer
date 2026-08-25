package org.esupportail.publisher.aop.notification;

import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Before;
import org.esupportail.publisher.aop.notification.configuration.NotificationAspectConfig;
import org.esupportail.publisher.domain.*;
import org.esupportail.publisher.domain.enums.ContextType;
import fr.recia.notifications.event_rest_client_kafka.HttpNotificationClient;
import fr.recia.notifications.model_kafka.model.Channel;
import fr.recia.notifications.model_kafka.model.Priority;
import fr.recia.notifications.model_kafka.model.TargetType;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.esupportail.publisher.domain.enums.PermissionType;
import org.esupportail.publisher.domain.evaluators.AbstractEvaluator;
import org.esupportail.publisher.domain.evaluators.OperatorEvaluator;
import org.esupportail.publisher.domain.evaluators.UserGroupEvaluator;
import org.esupportail.publisher.repository.PermissionRepository;
import org.esupportail.publisher.repository.predicates.PermissionPredicates;
import org.esupportail.publisher.web.rest.dto.ContentDTO;
import org.springframework.stereotype.Component;

import org.esupportail.publisher.domain.enums.ItemStatus;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Component
@Aspect
@Slf4j
@Data
public class NotificationAspect {

    @PersistenceContext
    private EntityManager entityManager;

    @Inject
    private org.esupportail.publisher.repository.SubscriberRepository subscriberRepository;

    @Inject
    private final PermissionRepository<AbstractPermission> permissionRepository;

    private final NotificationAspectConfig notificationAspectConfig;

    private final HttpNotificationClient notificationClientModeration;
    private final HttpNotificationClient notificationClientNews;
    private final HttpNotificationClient notificationClientDoc;

    private final List<Channel> channels = List.of(Channel.WEB, Channel.PUSH, Channel.MAIL);

    private void sendNotificationsIndirect(AbstractItem item, HttpNotificationClient httpNotificationClient, String title, String link) throws Exception {
        final String message = item.getSummary();
        Iterable<Subscriber> targets = subscriberRepository.findAll(org.esupportail.publisher.repository.predicates.SubscriberPredicates.onCtx(item.getContextKey()));
        for (Subscriber target : targets) {
            final String targetId = target.getSubjectCtxId().getSubject().getKeyValue();
            final String uidRegex = "^F[a-zA-Z0-9]{7}$";
            if (targetId.matches(uidRegex)) {
                log.info("New notification to send to user {}", targetId);
                httpNotificationClient.sendNotification(title, message, link, targetId, channels, Priority.NORMAL, TargetType.UID);
            } else {
                log.info("New notification to send to group : {}", targetId);
                httpNotificationClient.sendNotification(title, message, link, targetId, channels, Priority.NORMAL, TargetType.GROUP);
            }
        }
    }

    private void sendNotificationsDirect(ContentDTO content, AbstractItem item, HttpNotificationClient httpNotificationClient, String title, String link) throws Exception {
        for (var target : content.getTargets()) {
            final String message = content.getItem().getSummary();
            final String uidRegex = "^F[a-zA-Z0-9]{7}$";
            final String targetId = target.getSubject().getModelId().getKeyId();
            if (targetId.matches(uidRegex)) {
                log.info("New notification to send to user {}", targetId);
                httpNotificationClient.sendNotification(title, message, link, targetId, channels, Priority.NORMAL, TargetType.UID);
            } else {
                log.info("New notification to send to group : {}", targetId);
                httpNotificationClient.sendNotification(title, message, link, targetId, channels, Priority.NORMAL, TargetType.GROUP);
            }
        }
    }


    @Before("execution(* org.esupportail.publisher.service.ContentService.publishScheduledContents(..))")
    public void notifScheduledPublished() {
        try {
            final String jpqlQuery = "select e from AbstractItem e " +
                "where e.status = org.esupportail.publisher.domain.enums.ItemStatus.SCHEDULED " +
                "and e.startDate is not null and e.startDate <= CURRENT_DATE";

            final List<AbstractItem> itemsToPublish = entityManager.createQuery(jpqlQuery, AbstractItem.class).getResultList();
            if (itemsToPublish.isEmpty()) {
                log.debug("Nothing to publish, no need to send any new notification");
                return;
            }

            for (AbstractItem item : itemsToPublish) {
                final String idLink = item.getId().toString();
                if (isNews(item)) {
                    final String title = notificationAspectConfig.getTitleNews();
                    final String link = notificationAspectConfig.getLinkNews().concat(idLink);
                    sendNotificationsIndirect(item, notificationClientNews, title, link);
                } else if (isDocument(item)) {
                    final String title = notificationAspectConfig.getTitleDoc();
                    final String link = notificationAspectConfig.getLinkDoc().concat(idLink);
                    sendNotificationsIndirect(item, notificationClientDoc, title, link);
                }
            }
        } catch (Exception e) {
            log.warn("Notification could not be sent", e);
        }
    }


    @After("execution(* org.esupportail.publisher.web.rest.ContentResource.create(..)) && args(content)")
    public void notifNoModeration(ContentDTO content) {
        final ItemStatus status = content.getItem().getStatus();
        if (status.equals(ItemStatus.PUBLISHED)) {
            AbstractItem item = content.getItem();
            final String idLink = item.getId().toString();
            try {
                if (isNews(item)) {
                    final String title = notificationAspectConfig.getTitleNews();
                    final String link = notificationAspectConfig.getLinkNews().concat(idLink);
                    sendNotificationsDirect(content, item, notificationClientNews, title, link);
                } else if (isDocument(item)) {
                    final String title = notificationAspectConfig.getTitleDoc();
                    final String link = notificationAspectConfig.getLinkDoc().concat(idLink);
                    sendNotificationsDirect(content, item, notificationClientDoc, title, link);
                }
            } catch (Exception e) {
                log.warn("Notification could not be sent", e);
            }
        } else {
            final String startDate = content.getItem().getStartDate().toString();
            log.info("Publication scheduled for {}", startDate);
        }
    }

    @AfterReturning("execution(* org.esupportail.publisher.service.ContentService.setValidationItem(..)) && args(.., item)")
    public void notifPublishedAfterModeration(AbstractItem item) {
        final String idLink = item.getId().toString();
        final ItemStatus status = item.getStatus();
        if(status.equals(ItemStatus.PUBLISHED)) {
            try {
                if (isNews(item)) {
                    final String title = notificationAspectConfig.getTitleNews();
                    final String link = notificationAspectConfig.getLinkNews().concat(idLink);
                    sendNotificationsIndirect(item, notificationClientNews, title, link);
                } else if (isDocument(item)) {
                    final String title = notificationAspectConfig.getTitleDoc();
                    final String link = notificationAspectConfig.getLinkDoc().concat(idLink);
                    sendNotificationsIndirect(item, notificationClientDoc, title, link);
                }
            } catch (Exception e) {
                log.warn("Notification couldn't be sent", e);
            }
        }
    }

    @After("execution(* org.esupportail.publisher.web.rest.ContentResource.create(..)) && args(content)")
    public void notifModeration(ContentDTO content) {
        try {
            final Long keyIdOrg = content.getItem().getOrganization().getId();
            final ContextType keyTypeOrg = content.getItem().getOrganization().getContextKey().getKeyType();
            final Iterable<AbstractPermission> perms = permissionRepository.findAll(PermissionPredicates.AbstractPermOnCtx(keyTypeOrg, keyIdOrg));
            final List<Channel> channel = List.of(Channel.WEB, Channel.PUSH, Channel.MAIL);
            final ItemStatus status = content.getItem().getStatus();
            final AbstractItem item = content.getItem();
            final String message = item.getSummary();
            if (status != ItemStatus.PUBLISHED) {
                final String title = notificationAspectConfig.getTitleModeration();
                final String link = notificationAspectConfig.getLinkModeration();
                for (AbstractPermission abstractPermission : perms) {
                    if (abstractPermission instanceof PermissionOnContext) {
                        final PermissionOnContext permission = (PermissionOnContext) abstractPermission;
                        if (PermissionType.MANAGER.equals(permission.getRole())) {
                            final AbstractEvaluator evaluator = permission.getEvaluator();
                            if (evaluator instanceof OperatorEvaluator) {
                                for (AbstractEvaluator subEval : ((OperatorEvaluator) evaluator).getEvaluators()) {
                                    if (subEval instanceof UserGroupEvaluator) {
                                        final String managerGroup = ((UserGroupEvaluator) subEval).getGroup();
                                        notificationClientModeration.sendNotification(title, message, link, managerGroup, channel, Priority.LOW, TargetType.GROUP);
                                    }
                                }
                            } else if (evaluator instanceof UserGroupEvaluator) {
                                final String managerGroup = ((UserGroupEvaluator) evaluator).getGroup();
                                notificationClientModeration.sendNotification(title, message, link, managerGroup, channel, Priority.LOW, TargetType.GROUP);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Notification could not be sent", e);
        }
    }

    private boolean isDocument(AbstractItem item) {
        return item instanceof Attachment;
    }

    private boolean isNews(AbstractItem item) {
        return item instanceof News;
    }
}
