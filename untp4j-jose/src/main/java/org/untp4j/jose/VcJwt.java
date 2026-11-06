package org.untp4j.jose;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEObjectType;

import java.util.Optional;

/** Constants and helpers shared by the {@code application/vc+jwt} signer and verifier. */
public final class VcJwt {

    /** JOSE {@code typ} for a secured verifiable credential (VC-JOSE-COSE §3.1.1). */
    public static final JOSEObjectType TYPE = new JOSEObjectType("vc+jwt");

    /** JOSE {@code cty} for the unsecured credential payload. */
    public static final String CONTENT_TYPE = "vc";

    /** Media type of a compact-serialised secured credential. */
    public static final String MEDIA_TYPE = "application/vc+jwt";

    private VcJwt() {
    }

    /**
     * Reads the issuer identifier of a credential, whether {@code issuer} is a URL string or an object.
     *
     * @param credential an unsecured credential
     * @return the issuer id, if present
     */
    public static Optional<String> issuerId(JsonNode credential) {
        JsonNode issuer = credential.path("issuer");
        if (issuer.isTextual()) {
            return Optional.of(issuer.asText());
        }
        JsonNode id = issuer.path("id");
        return id.isTextual() ? Optional.of(id.asText()) : Optional.empty();
    }

    /**
     * Returns the DID part of a DID URL such as {@code did:web:example.com#key-1}.
     *
     * @param didUrl a DID URL with a fragment
     * @return the DID without the fragment
     * @throws IllegalArgumentException if {@code didUrl} is not a DID URL with a non-empty fragment
     */
    public static String didOf(String didUrl) {
        int hash = didUrl.indexOf('#');
        if (!didUrl.startsWith("did:") || hash <= 4 || hash == didUrl.length() - 1) {
            throw new IllegalArgumentException("kid must be an absolute DID URL with a fragment: " + didUrl);
        }
        return didUrl.substring(0, hash);
    }
}
