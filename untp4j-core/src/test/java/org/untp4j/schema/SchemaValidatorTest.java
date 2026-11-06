package org.untp4j.schema;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.untp4j.CredentialType;
import org.untp4j.TestArtefacts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SchemaValidatorTest {

    private static SchemaValidator validator;

    @BeforeAll
    static void setUp() {
        validator = new SchemaValidator(TestArtefacts.store());
    }

    @ParameterizedTest
    @CsvSource({
            "DigitalProductPassport_battery_instance, DIGITAL_PRODUCT_PASSPORT",
            "DigitalProductPassport_instance, DIGITAL_PRODUCT_PASSPORT",
            "DigitalIdentityAnchor_battery_instance, DIGITAL_IDENTITY_ANCHOR",
            "ConformityCredential_battery_instance, DIGITAL_CONFORMITY_CREDENTIAL",
            "DigitalFacilityRecord_battery_instance, DIGITAL_FACILITY_RECORD",
            "DigitalTraceabilityEvent_battery_make_instance, DIGITAL_TRACEABILITY_EVENT"
    })
    void officialSamplesAreValid(String sample, CredentialType expectedType) {
        ValidationResult result = validator.validate(TestArtefacts.sample(sample));

        assertThat(result.type()).isEqualTo(expectedType);
        assertThat(result.violations()).isEmpty();
    }

    @Test
    void missingRequiredPropertyIsReported() {
        ObjectNode dpp = TestArtefacts.sample("DigitalProductPassport_battery_instance");
        dpp.remove("issuer");

        ValidationResult result = validator.validate(dpp);

        assertThat(result.isValid()).isFalse();
        assertThat(result.violations()).anySatisfy(v -> {
            assertThat(v.keyword()).isEqualTo("required");
            assertThat(v.message()).contains("issuer");
        });
    }

    @Test
    void typeArrayWithoutDppMarkerFailsAgainstDppSchema() {
        ObjectNode dpp = TestArtefacts.sample("DigitalProductPassport_battery_instance");
        dpp.putArray("type").add("VerifiableCredential");

        ValidationResult result = validator.validate(CredentialType.DIGITAL_PRODUCT_PASSPORT, dpp);

        assertThat(result.isValid()).isFalse();
    }

    @Test
    void credentialNamingTwoUntpTypesIsRejected() {
        ObjectNode dpp = TestArtefacts.sample("DigitalProductPassport_battery_instance");
        dpp.withArray("type").add("DigitalConformityCredential");

        assertThatThrownBy(() -> validator.validate(dpp))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
