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

import jakarta.annotation.Nullable;
import org.esupportail.filemanager.beans.RedisProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Component
public class CustomSessionMappingStorage {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CustomSessionMappingStorage.class);

    @Autowired
    RedisProperties redisProperties;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    protected String prefixedKeyMapping(String key){
        return String.format("%1$s:%2$s",redisProperties.getMappingPrefix(),key);
    }

    protected String prefixedKeyReverseMapping(String key){
        return String.format("%1$s:%2$s",redisProperties.getReverseMappingPrefix(),key);
    }

    public void setSessionTicketSessionIdPair(String sessionTicket, String sessionId) {
        log.trace("[CustomSessionMappingStorage] setSessionTicketSessionIdPair {} {}", sessionTicket, sessionId);
        redisTemplate.opsForValue().set(prefixedKeyMapping(sessionTicket), sessionId,8, TimeUnit.HOURS);

        redisTemplate.opsForValue().set(prefixedKeyReverseMapping(sessionId), "",8, TimeUnit.HOURS);
    }

    public String getSessionIdFromSessionTicket(String sessionTicket) {
        log.trace("[CustomSessionMappingStorage] getSessionIdFromSessionTicket {}", sessionTicket);
        return redisTemplate.opsForValue().get(prefixedKeyMapping(sessionTicket));
    }


    public boolean hasSessionId(String sessionId){
        String value = redisTemplate.opsForValue().get(prefixedKeyReverseMapping(sessionId));
        return Objects.nonNull(value);
    }

    public void removeSessionTicket(String sessionTicket) {
        log.trace("[CustomSessionMappingStorage] removeSessionTicket {}", sessionTicket);
        String sessionId = redisTemplate.opsForValue().getAndDelete(prefixedKeyMapping(sessionTicket));

        if(Objects.nonNull(sessionId) && !sessionId.isEmpty()){
            redisTemplate.delete(prefixedKeyReverseMapping(sessionId));
        }
    }
}
