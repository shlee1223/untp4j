package org.untp4j.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.resource.InputStreamSource;
import org.untp4j.CredentialType;
import org.untp4j.artefact.ArtefactStore;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Validates unsecured UNTP credentials against their published JSON schemas.
 *
 * <p>Schemas are only ever read from the given {@link ArtefactStore}; any {@code $ref}
 * to an unpinned location fails instead of being fetched from the network.
 */
public final class SchemaValidator {

    private final Map<CredentialType, JsonSchema> schemas = new EnumMap<>(CredentialType.class);

    public SchemaValidator(ArtefactStore store) {
        Objects.requireNonNull(store, "store");
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012,
                builder -> builder.schemaLoaders(loaders -> loaders.values(list -> {
                    list.clear();
                    list.add(iri -> {
                        URI url = URI.create(iri.toString());
                        if (!isHttp(url)) {
                            return null; // let the factory resolve built-in meta-schemas
                        }
                        byte[] bytes = store.load(url);
                        return (InputStreamSource) () -> new ByteArrayInputStream(bytes);
                    });
                })));
        SchemaValidatorsConfig config = SchemaValidatorsConfig.builder()
                .formatAssertionsEnabled(true)
                .build();
        for (CredentialType type : CredentialType.values()) {
            schemas.put(type, factory.getSchema(SchemaLocation.of(type.schemaUrl().toString()), config));
        }
    }

    /**
     * Validates a credential as the UNTP type named in its {@code type} array.
     *
     * @param credential an unsecured credential
     * @return the validation result
     * @throws IllegalArgumentException if the credential does not name exactly one UNTP type
     */
    public ValidationResult validate(JsonNode credential) {
        CredentialType type = CredentialType.detect(credential).orElseThrow(() ->
                new IllegalArgumentException("Credential type array must name exactly one UNTP credential type"));
        return validate(type, credential);
    }

    /**
     * Validates a credential against the schema for {@code type}.
     *
     * @param type the UNTP type to validate as
     * @param credential an unsecured credential
     * @return the validation result
     */
    public ValidationResult validate(CredentialType type, JsonNode credential) {
        List<Violation> violations = schemas.get(type).validate(credential).stream()
                .map(SchemaValidator::toViolation)
                .sorted(Comparator.comparing(Violation::path).thenComparing(Violation::message))
                .toList();
        return new ValidationResult(type, violations);
    }

    private static Violation toViolation(ValidationMessage m) {
        return new Violation(String.valueOf(m.getInstanceLocation()), m.getType(), m.getMessage());
    }

    private static boolean isHttp(URI url) {
        String scheme = url.getScheme();
        return "https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme);
    }
}
