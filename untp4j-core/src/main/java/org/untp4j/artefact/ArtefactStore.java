package org.untp4j.artefact;

import java.net.URI;

/**
 * Serves UNTP artefacts by URL. Implementations must only return bytes that match a pin;
 * they must never fall back to an unverified network fetch.
 */
public interface ArtefactStore {

    /**
     * @param url canonical artefact URL
     * @return the verified artefact bytes
     * @throws ArtefactException if the URL is not pinned or the bytes do not match the pin
     */
    byte[] load(URI url);
}
