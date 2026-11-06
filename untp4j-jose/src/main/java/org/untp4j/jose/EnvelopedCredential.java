package org.untp4j.jose;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The VCDM 2.0 {@code EnvelopedVerifiableCredential} wrapper: a JSON object whose {@code id} is a
 * {@code data:application/vc+jwt,} URL holding the compact JWS. This is the form UNTP tools exchange.
 */
public final class EnvelopedCredential {

    public static final String TYPE = "EnvelopedVerifiableCredential";
    public static final String CONTEXT = "https://www.w3.org/ns/credentials/v2";
    private static final String DATA_PREFIX = "data:" + VcJwt.MEDIA_TYPE + ",";

    private EnvelopedCredential() {
    }

    /**
     * @param compactJws a secured credential
     * @return the enveloped credential
     */
    public static ObjectNode wrap(String compactJws) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("@context", CONTEXT);
        node.put("id", DATA_PREFIX + compactJws);
        node.put("type", TYPE);
        return node;
    }

    /**
     * @param enveloped an enveloped credential
     * @return the compact JWS it carries
     * @throws VcJwtException if the object is not a {@code vc+jwt} enveloped credential
     */
    public static String unwrap(JsonNode enveloped) {
        if (!TYPE.equals(enveloped.path("type").asText())) {
            throw new VcJwtException("type must be " + TYPE);
        }
        String id = enveloped.path("id").asText();
        if (!id.startsWith(DATA_PREFIX)) {
            throw new VcJwtException("id must start with " + DATA_PREFIX);
        }
        return id.substring(DATA_PREFIX.length());
    }
}
