package com.example.keycloak.push;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.util.JsonSerialization;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public final class PushCryptoUtils {

    private PushCryptoUtils() {
    }

    public static PublicKey publicKeyFromJwk(JsonNode jwkNode) {
        if (jwkNode == null || jwkNode.isMissingNode()) {
            throw new IllegalArgumentException("JWK is required");
        }

        String kty = jwkNode.path("kty").asText(null);
        if (!"RSA".equalsIgnoreCase(kty)) {
            throw new IllegalArgumentException("Only RSA JWKs are supported for this demo");
        }

        String n = jwkNode.path("n").asText(null);
        String e = jwkNode.path("e").asText(null);
        if (n == null || e == null) {
            throw new IllegalArgumentException("RSA JWK must contain 'n' and 'e'");
        }

        try {
            byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
            byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
            BigInteger modulus = new BigInteger(1, modulusBytes);
            BigInteger exponent = new BigInteger(1, exponentBytes);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to convert RSA JWK to PublicKey", ex);
        }
    }

    public static PublicKey publicKeyFromJwkString(String jwkJson) {
        if (jwkJson == null || jwkJson.isBlank()) {
            throw new IllegalArgumentException("JWK content is required");
        }
        try {
            JsonNode node = JsonSerialization.mapper.readTree(jwkJson);
            return publicKeyFromJwk(node);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to parse JWK", ex);
        }
    }
}
