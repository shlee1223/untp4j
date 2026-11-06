package org.untp4j.jose;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.util.Objects;

/**
 * Secures an unsecured credential as {@code application/vc+jwt}: the credential JSON itself is the
 * JWS payload, and {@code kid} is the DID URL of the issuer's verification method.
 */
public final class VcJwtSigner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JWSSigner signer;
    private final JWSAlgorithm algorithm;
    private final String kid;
    private final String issuerDid;

    /**
     * @param signer signs the JWS; may be backed by a KMS or HSM
     * @param algorithm JWS algorithm the signer produces
     * @param kid DID URL of the verification method, e.g. {@code did:web:example.com#key-1}
     */
    public VcJwtSigner(JWSSigner signer, JWSAlgorithm algorithm, String kid) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.kid = Objects.requireNonNull(kid, "kid");
        this.issuerDid = VcJwt.didOf(kid);
        if (!signer.supportedJWSAlgorithms().contains(algorithm)) {
            throw new IllegalArgumentException("Signer does not support " + algorithm);
        }
    }

    /**
     * Creates an ES256 signer from a P-256 private key whose {@code kid} is a DID URL.
     *
     * @param key P-256 private key with {@code kid} set
     * @return the signer
     * @throws JOSEException if the key cannot sign
     */
    public static VcJwtSigner es256(ECKey key) throws JOSEException {
        if (!Curve.P_256.equals(key.getCurve()) || !key.isPrivate()) {
            throw new IllegalArgumentException("ES256 needs a private P-256 key");
        }
        return new VcJwtSigner(new ECDSASigner(key), JWSAlgorithm.ES256, key.getKeyID());
    }

    /** @return the {@code kid} placed in every JWS header */
    public String kid() {
        return kid;
    }

    /**
     * Signs a credential.
     *
     * @param credential an unsecured credential whose issuer is the DID in {@code kid}
     * @return the compact JWS
     * @throws IllegalArgumentException if the credential's issuer does not match the signing key
     * @throws JOSEException if signing fails
     */
    public String sign(JsonNode credential) throws JOSEException {
        String issuer = VcJwt.issuerId(credential)
                .orElseThrow(() -> new IllegalArgumentException("Credential has no issuer id"));
        if (!issuer.equals(issuerDid)) {
            throw new IllegalArgumentException("Credential issuer " + issuer + " does not match key " + kid);
        }
        JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(VcJwt.TYPE)
                .contentType(VcJwt.CONTENT_TYPE)
                .keyID(kid)
                .build();
        JWSObject jws;
        try {
            jws = new JWSObject(header, new Payload(MAPPER.writeValueAsString(credential)));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Credential cannot be serialised", e);
        }
        jws.sign(signer);
        return jws.serialize();
    }
}
