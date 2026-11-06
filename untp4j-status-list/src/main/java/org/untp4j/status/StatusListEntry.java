package org.untp4j.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.util.Objects;

/**
 * A {@code BitstringStatusListEntry}: points a credential at one bit of a status list credential.
 *
 * @param statusListCredential URL of the status list credential
 * @param index position of this credential's bit
 * @param purpose what a set bit means
 */
public record StatusListEntry(URI statusListCredential, long index, StatusPurpose purpose) {

    public static final String TYPE = "BitstringStatusListEntry";

    public StatusListEntry {
        Objects.requireNonNull(statusListCredential, "statusListCredential");
        Objects.requireNonNull(purpose, "purpose");
        if (index < 0) {
            throw new IllegalArgumentException("index must be >= 0");
        }
        if (!"https".equals(statusListCredential.getScheme()) || statusListCredential.getFragment() != null) {
            throw new IllegalArgumentException("statusListCredential must be an https URL without fragment");
        }
    }

    /**
     * Serialises the entry. {@code statusListIndex} is written as a JSON integer because the UNTP 0.7.0
     * schemas require that, although the W3C spec describes a base-10 string; {@link #parse} accepts both.
     *
     * @return the {@code credentialStatus} object
     */
    public ObjectNode toJson() {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("id", statusListCredential + "#" + index);
        node.put("type", TYPE);
        node.put("statusPurpose", purpose.value());
        node.put("statusListIndex", index);
        node.put("statusListCredential", statusListCredential.toString());
        return node;
    }

    /**
     * @param node a {@code credentialStatus} object
     * @return the entry
     * @throws StatusListException if it is not a supported {@code BitstringStatusListEntry}
     */
    public static StatusListEntry parse(JsonNode node) {
        if (!TYPE.equals(node.path("type").asText())) {
            throw new StatusListException("Unsupported credentialStatus type: " + node.path("type"));
        }
        StatusPurpose purpose = StatusPurpose.of(node.path("statusPurpose").asText())
                .orElseThrow(() -> new StatusListException("Unsupported statusPurpose: " + node.path("statusPurpose")));
        JsonNode rawIndex = node.path("statusListIndex");
        long index;
        try {
            if (rawIndex.isIntegralNumber() && rawIndex.canConvertToLong()) {
                index = rawIndex.longValue();
            } else if (rawIndex.isTextual() && rawIndex.asText().matches("0|[1-9][0-9]{0,17}")) {
                index = Long.parseLong(rawIndex.asText());
            } else {
                throw new StatusListException("statusListIndex must be a non-negative integer: " + rawIndex);
            }
            return new StatusListEntry(URI.create(node.path("statusListCredential").asText()), index, purpose);
        } catch (IllegalArgumentException e) {
            throw new StatusListException("Invalid status entry: " + e.getMessage(), e);
        }
    }
}
