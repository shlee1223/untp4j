package org.untp4j.artefact;

import java.net.URI;

/** Raised when a UNTP artefact cannot be served from a trusted, pinned source. */
public class ArtefactException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final URI url;

    public ArtefactException(URI url, String message) {
        super(message);
        this.url = url;
    }

    public ArtefactException(URI url, String message, Throwable cause) {
        super(message, cause);
        this.url = url;
    }

    /** @return the artefact URL that could not be served */
    public URI url() {
        return url;
    }
}
