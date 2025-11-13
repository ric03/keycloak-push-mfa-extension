package com.example.keycloak.push;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PushCredentialData {

    private final String publicKeyJwk;
    private final String algorithm;
    private final long createdAt;
    private final String deviceType;
    private final String firebaseId;
    private final String pseudonymousUserId;

    @JsonCreator
    public PushCredentialData(@JsonProperty("publicKeyJwk") String publicKeyJwk,
                              @JsonProperty("algorithm") String algorithm,
                              @JsonProperty("createdAt") long createdAt,
                              @JsonProperty("deviceType") String deviceType,
                              @JsonProperty("firebaseId") String firebaseId,
                              @JsonProperty("pseudonymousUserId") String pseudonymousUserId) {
        this.publicKeyJwk = publicKeyJwk;
        this.algorithm = algorithm;
        this.createdAt = createdAt;
        this.deviceType = deviceType;
        this.firebaseId = firebaseId;
        this.pseudonymousUserId = pseudonymousUserId;
    }

    public String getPublicKeyJwk() {
        return publicKeyJwk;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public String getFirebaseId() {
        return firebaseId;
    }

    public String getPseudonymousUserId() {
        return pseudonymousUserId;
    }
}
