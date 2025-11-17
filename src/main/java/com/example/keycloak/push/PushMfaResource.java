package com.example.keycloak.push;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.util.JsonSerialization;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.security.PublicKey;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class PushMfaResource {

    private static final Logger LOG = Logger.getLogger(PushMfaResource.class);

    private final KeycloakSession session;
    private final PushChallengeStore challengeStore;

    public PushMfaResource(KeycloakSession session) {
        this.session = session;
        this.challengeStore = new PushChallengeStore(session);
    }

    @GET
    @Path("enroll/challenges/{challengeId}/events")
    @Produces(MediaType.SERVER_SENT_EVENTS)
    public void streamEnrollmentEvents(@PathParam("challengeId") String challengeId,
                                       @QueryParam("secret") String secret,
                                       @jakarta.ws.rs.core.Context SseEventSink sink,
                                       @jakarta.ws.rs.core.Context Sse sse) {
        if (sink == null || sse == null) {
            return;
        }
        LOG.infof("Received enrollment SSE stream request for challenge %s", challengeId);
        CompletableFuture.runAsync(() -> emitEnrollmentEvents(challengeId, secret, sink, sse));
    }

    @POST
    @Path("enroll/complete")
    public Response completeEnrollment(@Context HttpHeaders headers) {
        String deviceToken = requireDeviceAuthorization(headers);
        TokenLogHelper.logJwt("enroll-device-token", deviceToken);

        JWSInput deviceResponse;
        try {
            deviceResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid enrollment token");
        }

        Algorithm algorithm = deviceResponse.getHeader().getAlgorithm();
        if (algorithm == null || !algorithm.name().startsWith("RS")) {
            throw new BadRequestException("Unsupported signature algorithm: " + algorithm);
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(deviceResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse enrollment token");
        }

        String userId = require(jsonText(payload, "sub"), "sub");
        UserModel user = getUser(userId);

        String enrollmentId = require(jsonText(payload, "enrollmentId"), "enrollmentId");
        PushChallenge challenge = challengeStore.get(enrollmentId)
            .orElseThrow(() -> new NotFoundException("Challenge not found"));

        if (challenge.getType() != PushChallenge.Type.ENROLLMENT) {
            throw new BadRequestException("Challenge is not for enrollment");
        }

        if (!Objects.equals(challenge.getUserId(), user.getId())) {
            throw new ForbiddenException("Challenge does not belong to user");
        }

        if (challenge.getStatus() != PushChallengeStatus.PENDING) {
            throw new BadRequestException("Challenge already resolved or expired");
        }

        verifyTokenExpiration(payload.get("exp"), "enrollment token");

        String encodedNonce = require(jsonText(payload, "nonce"), "nonce");
        if (!Objects.equals(encodedNonce, PushChallengeStore.encodeNonce(challenge.getNonce()))) {
            throw new ForbiddenException("Nonce mismatch");
        }

        JsonNode cnf = payload.path("cnf");
        JsonNode jwkNode = cnf.path("jwk");
        if (jwkNode.isMissingNode() || jwkNode.isNull()) {
            throw new BadRequestException("Enrollment token is missing cnf.jwk claim");
        }

        PublicKey devicePublicKey = PushCryptoUtils.publicKeyFromJwk(jwkNode);
        if (devicePublicKey == null) {
            throw new BadRequestException("Unable to derive public key from cnf.jwk");
        }

        if (!RSAProvider.verify(deviceResponse, devicePublicKey)) {
            throw new ForbiddenException("Invalid enrollment token signature");
        }

        String deviceType = require(jsonText(payload, "deviceType"), "deviceType");
        String firebaseId = require(jsonText(payload, "firebaseId"), "firebaseId");
        String pseudonymousUserId = require(jsonText(payload, "pseudonymousUserId"), "pseudonymousUserId");
        String deviceId = require(jsonText(payload, "deviceId"), "deviceId");

        String labelClaim = jsonText(payload, "deviceLabel");
        String label = labelClaim == null || labelClaim.isBlank()
            ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME
            : labelClaim;

        PushCredentialData data = new PushCredentialData(
            jwkNode.toString(),
            algorithm.toString(),
            Instant.now().toEpochMilli(),
            deviceType,
            firebaseId,
            pseudonymousUserId,
            deviceId);
        CredentialModel credentialModel = PushCredentialService.createCredential(user, label, data);
        challengeStore.resolve(challenge.getId(), PushChallengeStatus.APPROVED);

        return Response.ok(Map.of("status", "enrolled")).build();
    }

    @GET
    @Path("login/pending")
    public Response listPendingChallenges(@jakarta.ws.rs.QueryParam("userId") String userId,
                                          @Context HttpHeaders headers) {
        String normalizedUserId = require(userId, "userId");
        DeviceAssertion device = authenticateDevice(headers);
        if (!Objects.equals(device.user().getId(), normalizedUserId)) {
            throw new ForbiddenException("Device token subject mismatch");
        }

        CredentialModel deviceCredential = device.credential();

        List<LoginChallenge> pending = challengeStore.findPendingForUser(realm().getId(), device.user().getId()).stream()
            .filter(challenge -> challenge.getType() == PushChallenge.Type.AUTHENTICATION)
            .filter(challenge -> Objects.equals(challenge.getCredentialId(), deviceCredential.getId()))
            .map(challenge -> new LoginChallenge(
                device.user().getId(),
                challenge.getId(),
                challenge.getExpiresAt(),
                challenge.getClientId()))
            .toList();
        return Response.ok(Map.of("challenges", pending)).build();
    }

    @POST
    @Path("login/challenges/{cid}/respond")
    public Response respondToChallenge(@PathParam("cid") String cid,
                                       @Context HttpHeaders headers) {
        String challengeId = require(cid, "cid");
        PushChallenge challenge = challengeStore.get(challengeId)
            .orElseThrow(() -> new NotFoundException("Challenge not found"));

        String challengeUserId = challenge.getUserId();

        if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            throw new BadRequestException("Challenge is not for login");
        }

        DeviceAssertion assertion = authenticateDevice(headers);
        TokenLogHelper.logJwt("login-device-token", assertion.token());

        UserModel user = assertion.user();
        if (!Objects.equals(user.getId(), challengeUserId)) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }

        CredentialModel credentialModel = assertion.credential();
        if (challenge.getCredentialId() != null && !Objects.equals(challenge.getCredentialId(), credentialModel.getId())) {
            throw new ForbiddenException("Authentication token device mismatch");
        }

        JsonNode payload = assertion.payload();

        String tokenAction = Optional.ofNullable(jsonText(payload, "action"))
            .map(String::toLowerCase)
            .orElse(PushMfaConstants.CHALLENGE_APPROVE);

        String tokenChallengeId = require(jsonText(payload, "cid"), "cid");
        if (!Objects.equals(tokenChallengeId, challengeId)) {
            throw new ForbiddenException("Challenge mismatch");
        }

        PushCredentialData data = assertion.credentialData();

        if (PushMfaConstants.CHALLENGE_DENY.equals(tokenAction)) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            return Response.ok(Map.of("status", "denied")).build();
        }

        if (!PushMfaConstants.CHALLENGE_APPROVE.equals(tokenAction)) {
            throw new BadRequestException("Unsupported action: " + tokenAction);
        }

        challengeStore.resolve(challengeId, PushChallengeStatus.APPROVED);
        return Response.ok(Map.of("status", "approved")).build();
    }

    @PUT
    @Path("device/firebase")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateDeviceFirebaseId(@Context HttpHeaders headers, UpdateFirebaseRequest request) {
        DeviceAssertion device = authenticateDevice(headers);
        String firebaseId = require(request.firebaseId(), "firebaseId");
        PushCredentialData current = device.credentialData();
        if (firebaseId.equals(current.getFirebaseId())) {
            return Response.ok(Map.of("status", "unchanged")).build();
        }
        PushCredentialData updated = new PushCredentialData(
            current.getPublicKeyJwk(),
            current.getAlgorithm(),
            current.getCreatedAt(),
            current.getDeviceType(),
            firebaseId,
            current.getPseudonymousUserId(),
            current.getDeviceId());
        PushCredentialService.updateCredential(device.user(), device.credential(), updated);
        LOG.infof("Updated Firebase ID for device %s (user=%s)", current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "updated")).build();
    }

    @PUT
    @Path("device/rotate-key")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response rotateDeviceKey(@Context HttpHeaders headers, RotateDeviceKeyRequest request) {
        DeviceAssertion device = authenticateDevice(headers);
        JsonNode jwkNode = Optional.ofNullable(request.publicKeyJwk())
            .orElseThrow(() -> new BadRequestException("Request missing publicKeyJwk"));
        String algorithm = require(request.algorithm(), "algorithm");

        PublicKey newPublicKey = PushCryptoUtils.publicKeyFromJwk(jwkNode);
        if (newPublicKey == null) {
            throw new BadRequestException("Unable to derive public key from publicKeyJwk");
        }

        PushCredentialData current = device.credentialData();
        PushCredentialData updated = new PushCredentialData(
            jwkNode.toString(),
            algorithm,
            Instant.now().toEpochMilli(),
            current.getDeviceType(),
            current.getFirebaseId(),
            current.getPseudonymousUserId(),
            current.getDeviceId());
        PushCredentialService.updateCredential(device.user(), device.credential(), updated);
        LOG.infof("Rotated device key for %s (user=%s)", current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "rotated")).build();
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private static String require(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new BadRequestException("Missing field: " + fieldName);
        }
        return value;
    }

    private static String jsonText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return value.asText(null);
    }

    private void verifyTokenExpiration(JsonNode expNode, String tokenDescription) {
        if (expNode == null || expNode.isNull()) {
            return;
        }
        long exp = expNode.asLong(Long.MIN_VALUE);
        if (exp != Long.MIN_VALUE && Instant.now().getEpochSecond() > exp) {
            throw new BadRequestException(tokenDescription + " expired");
        }
    }

    private String requireDeviceAuthorization(HttpHeaders headers) {
        if (headers == null) {
            throw new NotAuthorizedException("Authorization header required");
        }
        String value = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (value == null || value.isBlank()) {
            throw new NotAuthorizedException("Device token required");
        }
        if (!value.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
            throw new NotAuthorizedException("Device token required");
        }
        String token = value.substring("Bearer ".length()).trim();
        if (token.isBlank()) {
            throw new NotAuthorizedException("Device token required");
        }
        return token;
    }

    private DeviceAssertion authenticateDevice(HttpHeaders headers) {
        String token = requireDeviceAuthorization(headers);
        return authenticateDevice(token);
    }

    private DeviceAssertion authenticateDevice(String deviceToken) {
        JWSInput assertion;
        try {
            assertion = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid device token");
        }

        Algorithm algorithm = assertion.getHeader().getAlgorithm();
        if (algorithm == null || !algorithm.name().startsWith("RS")) {
            throw new BadRequestException("Unsupported device token algorithm: " + algorithm);
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(assertion.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse device token");
        }

        verifyTokenExpiration(payload.get("exp"), "device token");

        String tokenSubject = require(jsonText(payload, "sub"), "sub");
        UserModel user = getUser(tokenSubject);

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        if (credentials.isEmpty()) {
            throw new ForbiddenException("Device not registered for user");
        }

        String tokenDeviceId = require(jsonText(payload, "deviceId"), "deviceId");

        CredentialModel credential = credentials.stream()
            .filter(model -> {
                PushCredentialData credentialData = PushCredentialService.readCredentialData(model);
                return credentialData != null && tokenDeviceId.equals(credentialData.getDeviceId());
            })
            .findFirst()
            .orElseThrow(() -> new ForbiddenException("Device not registered for user"));

        PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
        if (credentialData == null || credentialData.getPublicKeyJwk() == null || credentialData.getPublicKeyJwk().isBlank()) {
            throw new BadRequestException("Stored credential missing JWK");
        }
        if (credentialData.getAlgorithm() != null && !algorithm.toString().equalsIgnoreCase(credentialData.getAlgorithm())) {
            throw new BadRequestException("Device token algorithm mismatch");
        }

        PublicKey publicKey;
        try {
            publicKey = PushCryptoUtils.publicKeyFromJwkString(credentialData.getPublicKeyJwk());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Stored credential contains invalid JWK");
        }
        if (publicKey == null) {
            throw new BadRequestException("Stored credential missing public key material");
        }

        if (!RSAProvider.verify(assertion, publicKey)) {
            throw new ForbiddenException("Invalid device token signature");
        }

        return new DeviceAssertion(deviceToken, user, credential, credentialData, payload, algorithm);
    }

    private void emitEnrollmentEvents(String challengeId,
                                      String secret,
                                      SseEventSink sink,
                                      Sse sse) {
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting enrollment SSE stream for challenge %s", challengeId);
            if (secret == null || secret.isBlank()) {
                LOG.infof("Enrollment SSE rejected for %s due to missing secret", challengeId);
                sendEnrollmentStatusEvent(eventSink, sse, "INVALID", null);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("Enrollment SSE challenge %s not found", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "NOT_FOUND", null);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();
                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("Enrollment SSE forbidden for %s due to secret mismatch", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "FORBIDDEN", null);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendEnrollmentStatusEvent(eventSink, sse, currentStatus.name(), challenge);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof("Enrollment SSE exiting for %s after reaching status %s", challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendEnrollmentStatusEvent(eventSink, sse, "INTERRUPTED", null);
                    LOG.infof("Enrollment SSE interrupted for %s", challengeId);
                    break;
                }
            }
            LOG.infof("Enrollment SSE stream closed for challenge %s", challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream enrollment events for %s", challengeId);
        }
    }

    private void sendEnrollmentStatusEvent(SseEventSink sink,
                                           Sse sse,
                                           String status,
                                           PushChallenge challenge) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            LOG.infof("Emitting enrollment SSE status %s for challenge %s", status, targetChallengeId);
            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            sink.send(sse.newEventBuilder()
                .name("status")
                .data(String.class, data)
                .build());
        } catch (Exception ex) {
            LOG.infof(ex, "Unable to send enrollment SSE status %s for %s", status, challenge != null ? challenge.getId() : "n/a");
        }
    }

    record LoginChallenge(@JsonProperty("userId") String userId,
                          @JsonProperty("cid") String cid,
                          @JsonProperty("expiresAt") Instant expiresAt,
                          @JsonProperty("clientId") String clientId) {
    }

    record UpdateFirebaseRequest(@JsonProperty("firebaseId") String firebaseId) {
    }

    record RotateDeviceKeyRequest(@JsonProperty("publicKeyJwk") JsonNode publicKeyJwk,
                                  @JsonProperty("algorithm") String algorithm) {
    }

    record DeviceAssertion(String token,
                           UserModel user,
                           CredentialModel credential,
                           PushCredentialData credentialData,
                           JsonNode payload,
                           Algorithm algorithm) {
    }
}
