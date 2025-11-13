package com.example.keycloak.push;

import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

final class TokenLogHelper {

    private static final Logger LOG = Logger.getLogger(TokenLogHelper.class);

    private TokenLogHelper() {
    }

    static void logJwt(String label, String token) {
        if (token == null || token.isBlank()) {
            LOG.infof("%s token: <empty>", label);
            return;
        }

        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            LOG.infof("%s token (non-JWT): %s", label, token);
            return;
        }

        try {
            String headerJson = decodePart(parts[0]);
            String payloadJson = decodePart(parts[1]);
            LOG.infof("%s token header=%s payload=%s", label, headerJson, payloadJson);
        } catch (Exception ex) {
            LOG.infof("%s token (decode error): %s", label, token);
        }
    }

    private static String decodePart(String segment) throws Exception {
        String normalized = segment + "=".repeat((4 - segment.length() % 4) % 4);
        byte[] decoded = Base64.getUrlDecoder().decode(normalized);
        Object json = JsonSerialization.mapper.readTree(decoded);
        return JsonSerialization.writeValueAsString(json);
    }
}
