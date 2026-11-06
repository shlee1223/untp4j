package org.untp4j.status;

import java.util.Arrays;
import java.util.Optional;

/** Bitstring status purposes with single-bit entries. */
public enum StatusPurpose {

    /** Permanent: a set bit means the credential is revoked. */
    REVOCATION("revocation"),
    /** Temporary: a set bit means the credential is suspended. */
    SUSPENSION("suspension");

    private final String value;

    StatusPurpose(String value) {
        this.value = value;
    }

    /** @return the JSON value, e.g. {@code revocation} */
    public String value() {
        return value;
    }

    /**
     * @param value JSON value
     * @return the purpose, if supported
     */
    public static Optional<StatusPurpose> of(String value) {
        return Arrays.stream(values()).filter(p -> p.value.equals(value)).findFirst();
    }
}
