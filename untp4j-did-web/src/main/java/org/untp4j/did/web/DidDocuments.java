package org.untp4j.did.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.JWK;

/** Builds DID documents that publish JOSE verification keys. */
public final class DidDocuments {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private DidDocuments() {
    }

    /**
     * Creates a DID document with one {@code JsonWebKey} verification method usable for issuing
     * credentials ({@code assertionMethod}).
     *
     * @param did the DID the document describes
     * @param publicKey the public key; its {@code kid} must be {@code did + "#" + fragment}
     * @return the DID document
     * @throws IllegalArgumentException if the key is private or its kid is not a fragment of {@code did}
     */
    public static ObjectNode withAssertionKey(String did, JWK publicKey) {
        if (publicKey.isPrivate()) {
            throw new IllegalArgumentException("Refusing to publish private key material");
        }
        String kid = publicKey.getKeyID();
        if (kid == null || !kid.startsWith(did + "#") || kid.length() == did.length() + 1) {
            throw new IllegalArgumentException("Key id must be a fragment of " + did + ": " + kid);
        }
        DidWeb.documentUrl(did);

        ObjectNode doc = MAPPER.createObjectNode();
        doc.putArray("@context")
                .add("https://www.w3.org/ns/did/v1")
                .add("https://w3id.org/security/jwk/v1");
        doc.put("id", did);
        ArrayNode methods = doc.putArray("verificationMethod");
        ObjectNode method = methods.addObject();
        method.put("id", kid);
        method.put("type", "JsonWebKey");
        method.put("controller", did);
        method.set("publicKeyJwk", MAPPER.valueToTree(publicKey.toJSONObject()));
        doc.putArray("assertionMethod").add(kid);
        return doc;
    }
}
