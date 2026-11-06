package org.untp4j.jose;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VcJwtTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID = "did:web:issuer.example";
    private static final String KID = DID + "#key-1";

    private ECKey key;
    private VcJwtVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
        verifier = new VcJwtVerifier(kid -> {
            if (!KID.equals(kid)) {
                throw new VcJwtException("unknown kid " + kid);
            }
            return key.toPublicJWK();
        });
    }

    private static ObjectNode credential(String issuer) {
        ObjectNode vc = MAPPER.createObjectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");
        vc.putArray("type").add("VerifiableCredential").add("DigitalProductPassport");
        vc.putObject("issuer").put("id", issuer).put("name", "Issuer");
        vc.putObject("credentialSubject").put("id", "https://issuer.example/product/1");
        return vc;
    }

    @Test
    void signsAndVerifiesRoundTrip() throws Exception {
        ObjectNode vc = credential(DID);
        String jwt = VcJwtSigner.es256(key).sign(vc);

        JWSHeader header = JWSObject.parse(jwt).getHeader();
        assertThat(header.getType()).isEqualTo(VcJwt.TYPE);
        assertThat(header.getContentType()).isEqualTo("vc");
        assertThat(header.getKeyID()).isEqualTo(KID);

        VerifiedCredential verified = verifier.verify(jwt);
        assertThat(verified.credential()).isEqualTo(vc);
        assertThat(verified.algorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void signerRefusesCredentialOfAnotherIssuer() throws Exception {
        VcJwtSigner signer = VcJwtSigner.es256(key);

        assertThatThrownBy(() -> signer.sign(credential("did:web:someone-else.example")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        String[] parts = VcJwtSigner.es256(key).sign(credential(DID)).split("\\.");
        String forged = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MAPPER.writeValueAsString(credential(DID).put("name", "forged")).getBytes(UTF_8));

        assertThatThrownBy(() -> verifier.verify(parts[0] + "." + forged + "." + parts[2]))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("Signature");
    }

    @Test
    void rejectsKeyFromDifferentDidThanIssuer() throws Exception {
        // Attacker signs with their own DID key a credential claiming the victim as issuer.
        String attackerKid = "did:web:attacker.example#key-1";
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID(attackerKid).generate();
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(VcJwt.TYPE).keyID(attackerKid).build(),
                new Payload(MAPPER.writeValueAsString(credential(DID))));
        jws.sign(new ECDSASigner(attacker));
        VcJwtVerifier trustsAttackerKey = new VcJwtVerifier(kid -> attacker.toPublicJWK());

        assertThatThrownBy(() -> trustsAttackerKey.verify(jws.serialize()))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void rejectsHmacAlgorithmConfusion() throws Exception {
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(VcJwt.TYPE).keyID(KID).build(),
                new Payload(MAPPER.writeValueAsString(credential(DID))));
        jws.sign(new MACSigner(new byte[32]));

        assertThatThrownBy(() -> verifier.verify(jws.serialize()))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("Algorithm not allowed");
    }

    @Test
    void rejectsWrongTyp() throws Exception {
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(KID).build(),
                new Payload(MAPPER.writeValueAsString(credential(DID))));
        jws.sign(new ECDSASigner(key));

        assertThatThrownBy(() -> verifier.verify(jws.serialize()))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("typ");
    }

    @Test
    void rejectsKidThatIsNotADidUrl() throws Exception {
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(VcJwt.TYPE).keyID("key-1").build(),
                new Payload(MAPPER.writeValueAsString(credential(DID))));
        jws.sign(new ECDSASigner(key));

        assertThatThrownBy(() -> verifier.verify(jws.serialize()))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("DID URL");
    }

    @Test
    void rejectsResolvedPrivateKey() throws Exception {
        VcJwtVerifier leaky = new VcJwtVerifier(kid -> key);

        assertThatThrownBy(() -> leaky.verify(VcJwtSigner.es256(key).sign(credential(DID))))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("private");
    }

    @Test
    void envelopeRoundTrip() throws Exception {
        String jwt = VcJwtSigner.es256(key).sign(credential(DID));
        ObjectNode enveloped = EnvelopedCredential.wrap(jwt);

        assertThat(enveloped.path("type").asText()).isEqualTo("EnvelopedVerifiableCredential");
        assertThat(enveloped.path("id").asText()).startsWith("data:application/vc+jwt,ey");
        assertThat(EnvelopedCredential.unwrap(enveloped)).isEqualTo(jwt);
    }
}
