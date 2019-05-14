/*
 * Copyright 2018-present Open Networking Foundation
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

package org.opencord.kafka.integrations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.device.DeviceService;
import org.opencord.aaa.AuthenticationEvent;
import org.opencord.aaa.AuthenticationEventListener;
import org.opencord.aaa.AuthenticationService;

//added import for StatEvents

import org.opencord.aaa.AuthenticationStatisticsEvent;
import org.opencord.aaa.AuthenticationStatisticsEventListener;
import org.opencord.aaa.AuthenticationStatisticsService;

import org.opencord.kafka.EventBusService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Listens for AAA events and pushes them on a Kafka bus.
 */
@Component(immediate = true)
public class AaaKafkaIntegration {

    public Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected EventBusService eventBusService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY,
            bind = "bindAuthenticationService",
            unbind = "unbindAuthenticationService")
    protected AuthenticationService authenticationService;
    
    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY,
            bind = "bindAuthenticationStatService",
            unbind = "unbindAuthenticationStatService")
    protected AuthenticationStatisticsService authenticationStatisticsService;

    private final AuthenticationEventListener listener = new InternalAuthenticationListener();
    private final AuthenticationStatisticsEventListener authenticationStatisticsEventListener = new InternalAuthenticationStatisticsListner();
    

    private static final String TOPIC = "authentication.events";

    private static final String TIMESTAMP = "timestamp";
    private static final String DEVICE_ID = "deviceId";
    private static final String PORT_NUMBER = "portNumber";
    private static final String SERIAL_NUMBER = "serialNumber";
    private static final String AUTHENTICATION_STATE = "authenticationState";
    
    private static final String AUTHENTICATION_STATISTICS_TOPIC = "authstats.kpis";
    private static final String AUTHENTICATION_STATISTICS_STATE = "authenticationStatisticsState";
    private static final String ACCEPT_PACKET_COUNTER = "acceptPacketCounter";
    private static final String REJECT_PACKET_COUNTER = "rejectPacketCounter";
    private static final String CHALLENGE_PACKET_COUNTER = "challengePacketCounter";
    private static final String ACCESS_PACKET_COUNTER = "accessPacketCounter";
    private static final String INVALID_VALIDATOR_COUNTER = "invalidValidatorCounter";
    private static final String UNKNOWN_TYPE_COUNTER = "unknownTypeCounter";
    private static final String PENDING_REQUEST_COUNTER = "pendingRequestCounter";
    private static final String NUMBER_OF_DROPPED_PACKETS = "numberOfDroppedPackets";
    private static final String MALFORMED_PACKET_COUNTERS = "malformed_packet_counter";
    private static final String NUMBER_OF_PACKET_FROM_UNKNOWN_SERVER = "numberOfPacketFromUnknownServer";
    private static final String PACKET_ROUND_TRIP_TIME_IN_MILLS = "packetRoundtripTimeInMilis";

    protected void bindAuthenticationService(AuthenticationService authenticationService) {
        if (this.authenticationService == null) {
            log.info("Binding AuthenticationService");
            this.authenticationService = authenticationService;
            log.info("Adding listener on AuthenticationService");
            authenticationService.addListener(listener);
        } else {
            log.warn("Trying to bind AuthenticationService but it is already bound");
        }
    }

    protected void unbindAuthenticationService(AuthenticationService authenticationService) {
        if (this.authenticationService == authenticationService) {
            log.info("Unbinding AuthenticationService");
            this.authenticationService = null;
            log.info("Removing listener on AuthenticationService");
            authenticationService.removeListener(listener);
        } else {
            log.warn("Trying to unbind AuthenticationService but it is already unbound");
        }
    }
    
    
    protected void bindAuthenticationStatService(AuthenticationStatisticsService authenticationStatisticsService) {
        if (this.authenticationStatisticsService == null) {
            log.info("Binding AuthenticationStastService");
            this.authenticationStatisticsService = authenticationStatisticsService;
            log.info("Adding listener on AuthenticationStatService");
            authenticationStatisticsService.addListener(authenticationStatisticsEventListener);
        } else {
            log.warn("Trying to bind AuthenticationStatService but it is already bound");
        }
    }

    protected void unbindAuthenticationStatService(AuthenticationStatisticsService authenticationStatisticsService) {
        if (this.authenticationStatisticsService == authenticationStatisticsService) {
            log.info("Unbinding AuthenticationStatService");
            this.authenticationStatisticsService = null;
            log.info("Removing listener on AuthenticationStatService");
            authenticationStatisticsService.removeListener(authenticationStatisticsEventListener);
        } else {
            log.warn("Trying to unbind AuthenticationStatService but it is already unbound");
        }
    }
    
    

    @Activate
    public void activate() {
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        log.info("Stopped");
    }

    private void handle(AuthenticationEvent event) {
        eventBusService.send(TOPIC, serialize(event));
    }
    
    private void handleStat(AuthenticationStatisticsEvent event) {
        eventBusService.send(AUTHENTICATION_STATISTICS_TOPIC, serializeStat(event));
    }
    
    private JsonNode serialize(AuthenticationEvent event) {

        String sn = deviceService.getPort(event.subject()).annotations().value(AnnotationKeys.PORT_NAME);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode authEvent = mapper.createObjectNode();
        authEvent.put(TIMESTAMP, Instant.now().toString());
        authEvent.put(DEVICE_ID, event.subject().deviceId().toString());
        authEvent.put(PORT_NUMBER, event.subject().port().toString());
        authEvent.put(SERIAL_NUMBER, sn);
        authEvent.put(AUTHENTICATION_STATE, event.type().toString());
        return authEvent;
    }

    private JsonNode serializeStat(AuthenticationStatisticsEvent event) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode authMetricsEvent = mapper.createObjectNode();
        authMetricsEvent.put(TIMESTAMP, Instant.now().toString());
        authMetricsEvent.put(ACCEPT_PACKET_COUNTER, event.subject().getAcceptPacketsCounter());
        authMetricsEvent.put(REJECT_PACKET_COUNTER, event.subject().getRejectPacketsCounter());
        authMetricsEvent.put(CHALLENGE_PACKET_COUNTER, event.subject().getChallenegePacketsCounter());
        authMetricsEvent.put(ACCESS_PACKET_COUNTER, event.subject().getAccessPacketsCounter());
        authMetricsEvent.put(INVALID_VALIDATOR_COUNTER, event.subject().getInvalidValidatorCounter());
        authMetricsEvent.put(UNKNOWN_TYPE_COUNTER, event.subject().getUnknowPacketCounter());
        authMetricsEvent.put(PENDING_REQUEST_COUNTER, event.subject().getPendingRequestCounter());
        authMetricsEvent.put(NUMBER_OF_DROPPED_PACKETS, event.subject().getNumberOfDroppedPackets());
        authMetricsEvent.put(MALFORMED_PACKET_COUNTERS, event.subject().getMalformedPacketCounter());
        authMetricsEvent.put(NUMBER_OF_PACKET_FROM_UNKNOWN_SERVER, event.subject().getNumberOfPacketFromUnknownServer());
        authMetricsEvent.put(PACKET_ROUND_TRIP_TIME_IN_MILLS, event.subject().getPacketRoundtripTimeInMilis());
        authMetricsEvent.put(AUTHENTICATION_STATISTICS_STATE, event.type().toString());
        return authMetricsEvent;
    }
    
    private class InternalAuthenticationListener implements
            AuthenticationEventListener {

        @Override
        public void event(AuthenticationEvent authenticationEvent) {
            handle(authenticationEvent);
        }
    }
    
    private class InternalAuthenticationStatisticsListner implements
    AuthenticationStatisticsEventListener {

    	@Override
    	public void event(AuthenticationStatisticsEvent authenticationStatisticsEvent) {
    		handleStat(authenticationStatisticsEvent);
    	}
    }
}