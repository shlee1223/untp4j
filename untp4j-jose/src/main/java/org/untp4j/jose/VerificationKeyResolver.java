package org.untp4j.jose;

import com.nimbusds.jose.jwk.JWK;

/** Resolves the public key a {@code kid} DID URL refers to. */
@FunctionalInterface
public interface VerificationKeyResolver {

    /**
     * @param kid absolute DID URL of a verification method
     * @return the public key, authorised for issuing credentials (assertion method)
     * @throws VcJwtException if the key cannot be resolved or is not authorised
     */
    JWK resolve(String kid);
}
