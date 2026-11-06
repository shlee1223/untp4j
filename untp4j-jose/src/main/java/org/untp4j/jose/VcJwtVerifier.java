package org.untp4j.jose;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies {@code application/vc+jwt} credentials.
 *
 * <p>Beyond the signature itself it enforces: an explicit algorithm allow-list (no {@code none},
 * no HMAC), {@code typ: vc+jwt}, no {@code crit} extensions, a {@code kid} that is a DID URL of the
 * credential's own issuer, and a public key whose type and curve match the algorithm.
 */
public final class VcJwtVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<JWSAlgorithm, Curve> CURVES = Map.of(
            JWSAlgorithm.ES256, Curve.P_256,
            JWSAlgorithm.ES384, Curve.P_384);

    private final VerificationKeyResolver keys;
    private final Set<JWSAlgorithm> allowed;

    /** @param keys resolves {@code kid} DID URLs to public keys */
    public VcJwtVerifier(VerificationKeyResolver keys) {
        this(keys, Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384));
    }

    /**
     * @param keys resolves {@code kid} DID URLs to public keys
     * @param allowed accepted algorithms; a subset of ES256 and ES384
     */
    public VcJwtVerifier(VerificationKeyResolver keys, Set<JWSAlgorithm> allowed) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.allowed = Set.copyOf(allowed);
        if (this.allowed.isEmpty() || !CURVES.keySet().containsAll(this.allowed)) {
            throw new IllegalArgumentException("Supported algorithms are " + CURVES.keySet());
        }
    }

    /**
     * Verifies a compact JWS.
     *
     * @param compactJws the secured credential
     * @return the verified credential
     * @throws VcJwtException if any check fails
     */
    public VerifiedCredential verify(String compactJws) {
        JWSObject jws;
        try {
            jws = JWSObject.parse(compactJws);
        } catch (ParseException e) {
            throw new VcJwtException("Not a compact JWS", e);
        }
        JWSHeader header = jws.getHeader();
        JWSAlgorithm alg = header.getAlgorithm();
        if (!allowed.contains(alg)) {
            throw new VcJwtException("Algorithm not allowed: " + alg);
        }
        if (!VcJwt.TYPE.equals(header.getType())) {
            throw new VcJwtException("typ must be " + VcJwt.TYPE + " but was " + header.getType());
        }
        if (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty()) {
            throw new VcJwtException("Unsupported crit parameters: " + header.getCriticalParams());
        }
        String kid = header.getKeyID();
        if (kid == null) {
            throw new VcJwtException("Missing kid");
        }
        String keyDid;
        try {
            keyDid = VcJwt.didOf(kid);
        } catch (IllegalArgumentException e) {
            throw new VcJwtException(e.getMessage(), e);
        }

        // Resolve and check the signature before trusting anything in the payload.
        JWK jwk = keys.resolve(kid);
        boolean valid;
        try {
            valid = jws.verify(verifierFor(jwk, alg));
        } catch (JOSEException e) {
            throw new VcJwtException("Signature check failed", e);
        }
        if (!valid) {
            throw new VcJwtException("Signature does not verify");
        }

        JsonNode credential;
        try {
            credential = MAPPER.readTree(jws.getPayload().toString());
        } catch (JsonProcessingException e) {
            throw new VcJwtException("Payload is not JSON", e);
        }
        if (credential == null || !credential.isObject()) {
            throw new VcJwtException("Payload is not a JSON object");
        }
        String issuer = VcJwt.issuerId(credential)
                .orElseThrow(() -> new VcJwtException("Credential has no issuer id"));
        if (!issuer.equals(keyDid)) {
            throw new VcJwtException("Signed by " + keyDid + " but issuer is " + issuer);
        }
        return new VerifiedCredential(credential, kid, alg);
    }

    private static JWSVerifier verifierFor(JWK jwk, JWSAlgorithm alg) {
        if (jwk.isPrivate()) {
            throw new VcJwtException("Resolved key contains private material");
        }
        if (!(jwk instanceof ECKey ec) || !CURVES.get(alg).equals(ec.getCurve())) {
            throw new VcJwtException("Key " + jwk.getKeyType() + " does not match " + alg);
        }
        if (jwk.getAlgorithm() != null && !alg.equals(jwk.getAlgorithm())) {
            throw new VcJwtException("Key is restricted to " + jwk.getAlgorithm());
        }
        try {
            return new ECDSAVerifier(ec);
        } catch (JOSEException e) {
            throw new VcJwtException("Unusable key", e);
        }
    }
}
