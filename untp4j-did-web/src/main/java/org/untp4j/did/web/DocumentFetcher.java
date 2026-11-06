package org.untp4j.did.web;

import java.io.IOException;
import java.net.URI;

/** Retrieves the raw bytes of a DID document. */
@FunctionalInterface
public interface DocumentFetcher {

    /**
     * @param url DID document URL
     * @return the document bytes
     * @throws IOException if the document cannot be retrieved
     */
    byte[] fetch(URI url) throws IOException;
}
