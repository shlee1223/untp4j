package org.untp4j.artefact;

import java.net.URI;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A published UNTP artefact (JSON schema or JSON-LD context) pinned to the SHA-256 of its exact bytes.
 *
 * @param url canonical URL the artefact is published at
 * @param file relative path of the local copy inside an artefact directory
 * @param sha256 lowercase hex SHA-256 of the artefact bytes
 */
public record ArtefactPin(URI url, String file, String sha256) {

    public ArtefactPin {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(sha256, "sha256");
        if (sha256.length() != 64 || !sha256.chars().allMatch(HexFormat::isHexDigit)) {
            throw new IllegalArgumentException("sha256 must be 64 hex characters: " + sha256);
        }
        sha256 = sha256.toLowerCase(java.util.Locale.ROOT);
    }
}
