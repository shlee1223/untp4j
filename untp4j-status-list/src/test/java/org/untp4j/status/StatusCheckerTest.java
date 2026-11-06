package org.untp4j.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.untp4j.jose.EnvelopedCredential;
import org.untp4j.jose.VcJwtException;
import org.untp4j.jose.VcJwtSigner;
import org.untp4j.jose.VcJwtVerifier;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StatusCheckerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID = "did:web:issuer.example";
    private static final String OTHER_DID = "did:web:other.example";
    private static final URI LIST = URI.create("https://issuer.example/status/revocation/1.json");
    private static final Instant NOW = Instant.parse("2026-11-07T00:00:00Z");

    private final Map<URI, byte[]> published = new HashMap<>();
    private final Map<String, ECKey> keys = new HashMap<>();
    private StatusChecker checker;

    @BeforeEach
    void setUp() throws Exception {
        keys.put(DID, new ECKeyGenerator(Curve.P_256).keyID(DID + "#key-1").generate());
        keys.put(OTHER_DID, new ECKeyGenerator(Curve.P_256).keyID(OTHER_DID + "#key-1").generate());
        VcJwtVerifier verifier = new VcJwtVerifier(kid -> {
            ECKey key = keys.get(kid.substring(0, kid.indexOf('#')));
            if (key == null) {
                throw new VcJwtException("unknown " + kid);
            }
            return key.toPublicJWK();
        });
        checker = new StatusChecker(url -> {
            byte[] body = published.get(url);
            if (body == null) {
                throw new IOException("404 " + url);
            }
            return body;
        }, verifier, Clock.fixed(NOW, ZoneOffset.UTC), Bitstring.DEFAULT_MAX_BYTES);
    }

    private void publish(String signerDid, ObjectNode list) throws Exception {
        String jwt = VcJwtSigner.es256(keys.get(signerDid)).sign(list);
        published.put(LIST, MAPPER.writeValueAsBytes(EnvelopedCredential.wrap(jwt)));
    }

    private static ObjectNode list(String issuer, StatusPurpose purpose, long... revoked) {
        Bitstring bits = Bitstring.empty();
        for (long i : revoked) {
            bits.set(i, true);
        }
        return StatusListCredentials.create(issuer, LIST, purpose, bits, NOW.minusSeconds(60));
    }

    private static ObjectNode credential(long index, StatusPurpose purpose) {
        ObjectNode vc = MAPPER.createObjectNode();
        vc.putObject("issuer").put("id", DID);
        vc.set("credentialStatus", new StatusListEntry(LIST, index, purpose).toJson());
        return vc;
    }

    @Test
    void reportsRevokedAndActiveCredentials() throws Exception {
        publish(DID, list(DID, StatusPurpose.REVOCATION, 42_137));

        assertThat(checker.check(credential(42_137, StatusPurpose.REVOCATION)))
                .singleElement().satisfies(c -> assertThat(c.revoked()).isTrue());
        assertThat(checker.check(credential(7, StatusPurpose.REVOCATION)))
                .singleElement().satisfies(c -> assertThat(c.revoked()).isFalse());
    }

    @Test
    void credentialWithoutStatusHasNoChecks() {
        ObjectNode vc = MAPPER.createObjectNode();
        vc.put("issuer", DID);

        assertThat(checker.check(vc)).isEmpty();
    }

    @Test
    void acceptsStringIndexPerW3cSpec() throws Exception {
        publish(DID, list(DID, StatusPurpose.REVOCATION, 5));
        ObjectNode vc = credential(5, StatusPurpose.REVOCATION);
        ((ObjectNode) vc.get("credentialStatus")).put("statusListIndex", "5");

        List<StatusCheck> checks = checker.check(vc);

        assertThat(checks.get(0).revoked()).isTrue();
    }

    @Test
    void rejectsListSignedByAnotherIssuer() throws Exception {
        // Someone else publishes a list at the URL claiming nothing is revoked.
        publish(OTHER_DID, list(OTHER_DID, StatusPurpose.REVOCATION));

        assertThatThrownBy(() -> checker.check(credential(42_137, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("differs from credential issuer");
    }

    @Test
    void rejectsPurposeMismatch() throws Exception {
        publish(DID, list(DID, StatusPurpose.SUSPENSION, 42_137));

        assertThatThrownBy(() -> checker.check(credential(42_137, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("purpose");
    }

    @Test
    void rejectsExpiredList() throws Exception {
        ObjectNode list = list(DID, StatusPurpose.REVOCATION);
        list.put("validUntil", NOW.minusSeconds(1).toString());
        publish(DID, list);

        assertThatThrownBy(() -> checker.check(credential(1, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsListServedFromWrongUrl() throws Exception {
        ObjectNode list = StatusListCredentials.create(DID, URI.create("https://issuer.example/status/other.json"),
                StatusPurpose.REVOCATION, Bitstring.empty(), NOW.minusSeconds(60));
        publish(DID, list);

        assertThatThrownBy(() -> checker.check(credential(1, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void rejectsUnsignedList() throws Exception {
        published.put(LIST, MAPPER.writeValueAsBytes(list(DID, StatusPurpose.REVOCATION)));

        assertThatThrownBy(() -> checker.check(credential(1, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class);
    }

    @Test
    void unreachableListFailsClosed() {
        assertThatThrownBy(() -> checker.check(credential(1, StatusPurpose.REVOCATION)))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("Cannot load");
    }

    @Test
    void acceptsCompactJwtBody() throws Exception {
        String jwt = VcJwtSigner.es256(keys.get(DID)).sign(list(DID, StatusPurpose.REVOCATION, 3));
        published.put(LIST, jwt.getBytes(StandardCharsets.US_ASCII));

        assertThat(checker.check(credential(3, StatusPurpose.REVOCATION)).get(0).revoked()).isTrue();
    }

    @Test
    void entryRejectsNonHttpsList() {
        assertThatThrownBy(() -> new StatusListEntry(URI.create("http://issuer.example/l"), 0, StatusPurpose.REVOCATION))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
