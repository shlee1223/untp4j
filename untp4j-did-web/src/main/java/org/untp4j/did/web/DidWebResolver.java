package org.untp4j.did.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import org.untp4j.jose.VcJwt;
import org.untp4j.jose.VcJwtException;
import org.untp4j.jose.VerificationKeyResolver;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

/**
 * Resolves {@code did:web} DIDs and their assertion keys.
 *
 * <p>A key is only returned if the DID document's {@code id} equals the DID, the verification
 * method's {@code id} equals the requested {@code kid}, its {@code controller} is the DID, and it is
 * referenced from {@code assertionMethod}.
 */
public final class DidWebResolver implements VerificationKeyResolver {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final DocumentFetcher fetcher;

    /** Creates a resolver that fetches DID documents over HTTPS. */
    public DidWebResolver() {
        this(new HttpsDocumentFetcher());
    }

    public DidWebResolver(DocumentFetcher fetcher) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
    }

    /**
     * @param did a {@code did:web}
     * @return its DID document
     * @throws VcJwtException if it cannot be resolved or its {@code id} does not match
     */
    public JsonNode resolveDocument(String did) {
        URI url;
        try {
            url = DidWeb.documentUrl(did);
        } catch (IllegalArgumentException e) {
            throw new VcJwtException(e.getMessage(), e);
        }
        JsonNode doc;
        try {
            doc = MAPPER.readTree(fetcher.fetch(url));
        } catch (IOException e) {
            throw new VcJwtException("Cannot resolve " + did + ": " + e.getMessage(), e);
        }
        if (doc == null || !doc.isObject()) {
            throw new VcJwtException("DID document for " + did + " is not a JSON object");
        }
        if (!did.equals(doc.path("id").asText())) {
            throw new VcJwtException("DID document id " + doc.path("id").asText() + " does not match " + did);
        }
        return doc;
    }

    @Override
    public JWK resolve(String kid) {
        String did;
        try {
            did = VcJwt.didOf(kid);
        } catch (IllegalArgumentException e) {
            throw new VcJwtException(e.getMessage(), e);
        }
        JsonNode doc = resolveDocument(did);
        String fragment = kid.substring(did.length());

        if (!isAssertionMethod(doc, kid, fragment)) {
            throw new VcJwtException(kid + " is not an assertionMethod of " + did);
        }
        JsonNode method = findMethod(doc, kid, fragment);
        if (method == null) {
            throw new VcJwtException("No verification method " + kid);
        }
        if (!did.equals(method.path("controller").asText())) {
            throw new VcJwtException("Verification method " + kid + " is not controlled by " + did);
        }
        JsonNode jwkNode = method.path("publicKeyJwk");
        if (!jwkNode.isObject()) {
            throw new VcJwtException("Verification method " + kid + " has no publicKeyJwk");
        }
        JWK jwk;
        try {
            jwk = JWK.parse(MAPPER.writeValueAsString(jwkNode));
        } catch (ParseException | JsonProcessingException e) {
            throw new VcJwtException("Invalid publicKeyJwk for " + kid, e);
        }
        if (jwk.isPrivate()) {
            throw new VcJwtException("DID document publishes private key material for " + kid);
        }
        return jwk;
    }

    private static boolean matches(String id, String kid, String fragment) {
        return kid.equals(id) || fragment.equals(id);
    }

    private static JsonNode findMethod(JsonNode doc, String kid, String fragment) {
        for (JsonNode m : doc.path("verificationMethod")) {
            if (matches(m.path("id").asText(), kid, fragment)) {
                return m;
            }
        }
        for (JsonNode m : doc.path("assertionMethod")) {
            if (m.isObject() && matches(m.path("id").asText(), kid, fragment)) {
                return m;
            }
        }
        return null;
    }

    private static boolean isAssertionMethod(JsonNode doc, String kid, String fragment) {
        for (JsonNode ref : doc.path("assertionMethod")) {
            String id = ref.isTextual() ? ref.asText() : ref.path("id").asText();
            if (matches(id, kid, fragment)) {
                return true;
            }
        }
        return false;
    }
}
