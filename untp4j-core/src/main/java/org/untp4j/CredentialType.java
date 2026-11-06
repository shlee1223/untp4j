package org.untp4j;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.Optional;

/** UNTP 0.7.0 credential types and their published JSON schemas. */
public enum CredentialType {

    DIGITAL_PRODUCT_PASSPORT("DigitalProductPassport", "dpp/DigitalProductPassport.json"),
    DIGITAL_CONFORMITY_CREDENTIAL("DigitalConformityCredential", "dcc/ConformityCredential.json"),
    DIGITAL_FACILITY_RECORD("DigitalFacilityRecord", "dfr/DigitalFacilityRecord.json"),
    DIGITAL_IDENTITY_ANCHOR("DigitalIdentityAnchor", "dia/DigitalIdentityAnchor.json"),
    DIGITAL_TRACEABILITY_EVENT("DigitalTraceabilityEvent", "dte/DigitalTraceabilityEvent.json");

    private static final String SCHEMA_BASE = "https://untp.unece.org/artefacts/schema/v0.7.0/";

    private final String typeName;
    private final URI schemaUrl;

    CredentialType(String typeName, String schemaPath) {
        this.typeName = typeName;
        this.schemaUrl = URI.create(SCHEMA_BASE + schemaPath);
    }

    /** @return the value this type takes in a credential's {@code type} array */
    public String typeName() {
        return typeName;
    }

    /** @return the canonical URL of the JSON schema for this type */
    public URI schemaUrl() {
        return schemaUrl;
    }

    /**
     * Detects the UNTP type from a credential's {@code type} array.
     *
     * @param credential an unsecured credential
     * @return the single UNTP type, or empty if there is none or more than one
     */
    public static Optional<CredentialType> detect(JsonNode credential) {
        JsonNode types = credential.path("type");
        if (!types.isArray()) {
            return Optional.empty();
        }
        CredentialType found = null;
        for (CredentialType candidate : values()) {
            for (JsonNode t : types) {
                if (candidate.typeName.equals(t.asText())) {
                    if (found != null && found != candidate) {
                        return Optional.empty();
                    }
                    found = candidate;
                }
            }
        }
        return Optional.ofNullable(found);
    }
}
