package org.untp4j.schema;

import org.untp4j.CredentialType;

import java.util.List;

/**
 * Outcome of validating a credential against its UNTP schema.
 *
 * @param type the UNTP type the credential was validated as
 * @param violations every violation found; empty when valid
 */
public record ValidationResult(CredentialType type, List<Violation> violations) {

    public ValidationResult {
        violations = List.copyOf(violations);
    }

    /** @return {@code true} if there are no violations */
    public boolean isValid() {
        return violations.isEmpty();
    }
}
