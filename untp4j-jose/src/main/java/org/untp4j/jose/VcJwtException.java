package org.untp4j.jose;

/** A secured credential failed verification. */
public class VcJwtException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public VcJwtException(String message) {
        super(message);
    }

    public VcJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
