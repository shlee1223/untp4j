package org.untp4j.jose;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * A credential whose {@code vc+jwt} signature was verified.
 *
 * @param credential the unsecured credential carried in the JWS payload
 * @param kid verification method that signed it
 * @param algorithm JWS algorithm used
 */
public record VerifiedCredential(JsonNode credential, String kid, JWSAlgorithm algorithm) {

    public VerifiedCredential {
        credential = credential.deepCopy();
    }

    @Override
    public JsonNode credential() {
        return credential.deepCopy();
    }
}
