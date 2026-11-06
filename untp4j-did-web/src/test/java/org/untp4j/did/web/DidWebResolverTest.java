package org.untp4j.did.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.untp4j.jose.VcJwtException;
import org.untp4j.jose.VcJwtSigner;
import org.untp4j.jose.VcJwtVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DidWebResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID = "did:web:issuer.example:demo";
    private static final String KID = DID + "#key-1";

    private ECKey key;
    private ObjectNode document;

    @BeforeEach
    void setUp() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).keyID(KID).generate();
        document = DidDocuments.withAssertionKey(DID, key.toPublicJWK());
    }

    private DidWebResolver resolverServing(ObjectNode doc) {
        return new DidWebResolver(url -> {
            assertThat(url).isEqualTo(URI.create("https://issuer.example/demo/did.json"));
            return MAPPER.writeValueAsBytes(doc);
        });
    }

    @Test
    void verifiesCredentialAgainstResolvedDidDocument() throws Exception {
        ObjectNode vc = MAPPER.createObjectNode();
        vc.putObject("issuer").put("id", DID);
        String jwt = VcJwtSigner.es256(key).sign(vc);

        assertThat(new VcJwtVerifier(resolverServing(document)).verify(jwt).kid()).isEqualTo(KID);
    }

    @Test
    void acceptsRelativeFragmentReferences() {
        ((ObjectNode) document.withArray("verificationMethod").get(0)).put("id", "#key-1");
        document.putArray("assertionMethod").add("#key-1");

        assertThat(resolverServing(document).resolve(KID)).isEqualTo(key.toPublicJWK());
    }

    @Test
    void rejectsKeyNotListedAsAssertionMethod() {
        document.putArray("assertionMethod");
        document.putArray("authentication").add(KID);

        assertThatThrownBy(() -> resolverServing(document).resolve(KID))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("assertionMethod");
    }

    @Test
    void rejectsDocumentForDifferentDid() {
        document.put("id", "did:web:attacker.example");

        assertThatThrownBy(() -> resolverServing(document).resolve(KID))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void rejectsMethodControlledByAnotherDid() {
        ((ObjectNode) document.withArray("verificationMethod").get(0)).put("controller", "did:web:attacker.example");

        assertThatThrownBy(() -> resolverServing(document).resolve(KID))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("controlled");
    }

    @Test
    void rejectsPublishedPrivateKey() {
        ((ObjectNode) document.withArray("verificationMethod").get(0))
                .set("publicKeyJwk", MAPPER.valueToTree(key.toJSONObject()));

        assertThatThrownBy(() -> resolverServing(document).resolve(KID))
                .isInstanceOf(VcJwtException.class)
                .hasMessageContaining("private");
    }

    @Test
    void documentBuilderRefusesPrivateKey() {
        assertThatThrownBy(() -> DidDocuments.withAssertionKey(DID, key))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void httpsFetcherRefusesPlainHttp() {
        assertThatThrownBy(() -> new HttpsDocumentFetcher().fetch(URI.create("http://issuer.example/did.json")))
                .hasMessageContaining("https");
    }
}
