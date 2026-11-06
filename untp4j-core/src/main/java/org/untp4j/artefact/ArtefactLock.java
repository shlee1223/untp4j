package org.untp4j.artefact;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The set of artefacts trusted for one UNTP version, each pinned by SHA-256. */
public final class ArtefactLock {

    private static final String UNTP_0_7_0 = "untp-0.7.0.lock.json";

    private final String untpVersion;
    private final Map<URI, ArtefactPin> pins;

    private ArtefactLock(String untpVersion, Map<URI, ArtefactPin> pins) {
        this.untpVersion = untpVersion;
        this.pins = Map.copyOf(pins);
    }

    /** @return the lock bundled with untp4j for UNTP 0.7.0 */
    public static ArtefactLock untp070() {
        try (InputStream in = ArtefactLock.class.getResourceAsStream(UNTP_0_7_0)) {
            if (in == null) {
                throw new IllegalStateException("Bundled lock file missing: " + UNTP_0_7_0);
            }
            return read(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Parses a lock file.
     *
     * @param in lock file JSON
     * @return the parsed lock
     * @throws IOException if the JSON cannot be read
     */
    public static ArtefactLock read(InputStream in) throws IOException {
        JsonNode root = new ObjectMapper().readTree(in);
        String version = root.path("untpVersion").asText(null);
        if (version == null) {
            throw new IOException("Lock file has no untpVersion");
        }
        Map<URI, ArtefactPin> pins = new LinkedHashMap<>();
        for (JsonNode a : root.path("artefacts")) {
            ArtefactPin pin = new ArtefactPin(
                    URI.create(a.path("url").asText()),
                    a.path("file").asText(),
                    a.path("sha256").asText());
            if (pins.put(pin.url(), pin) != null) {
                throw new IOException("Duplicate artefact URL in lock file: " + pin.url());
            }
        }
        return new ArtefactLock(version, pins);
    }

    /** @return the UNTP version this lock describes, e.g. {@code 0.7.0} */
    public String untpVersion() {
        return untpVersion;
    }

    /**
     * @param url artefact URL
     * @return the pin for {@code url}, if trusted
     */
    public Optional<ArtefactPin> pin(URI url) {
        return Optional.ofNullable(pins.get(url));
    }

    /** @return all pins */
    public List<ArtefactPin> pins() {
        return List.copyOf(pins.values());
    }
}
