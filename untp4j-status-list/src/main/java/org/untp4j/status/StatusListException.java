package org.untp4j.status;

/** A credential status could not be issued or established. */
public class StatusListException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public StatusListException(String message) {
        super(message);
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
