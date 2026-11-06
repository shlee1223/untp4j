package org.untp4j.artefact;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Serves pinned artefacts from a local directory, such as the output of the
 * {@code fetchUntpArtefacts} Gradle task. Every file is checked against its pin.
 */
public final class DirectoryArtefactStore implements ArtefactStore {

    private final Path root;
    private final ArtefactLock lock;
    private final Map<URI, byte[]> verified = new ConcurrentHashMap<>();

    public DirectoryArtefactStore(Path root, ArtefactLock lock) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.lock = Objects.requireNonNull(lock, "lock");
    }

    @Override
    public byte[] load(URI url) {
        byte[] bytes = verified.computeIfAbsent(url, this::readVerified);
        return bytes.clone();
    }

    private byte[] readVerified(URI url) {
        ArtefactPin pin = lock.pin(url)
                .orElseThrow(() -> new ArtefactException(url, "Artefact is not pinned: " + url));
        Path file = root.resolve(pin.file()).normalize();
        if (!file.startsWith(root)) {
            throw new ArtefactException(url, "Pinned file escapes artefact directory: " + pin.file());
        }
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new ArtefactException(url, "Cannot read pinned artefact " + file, e);
        }
        String actual = sha256(bytes);
        if (!actual.equals(pin.sha256())) {
            throw new ArtefactException(url,
                    "SHA-256 mismatch for " + url + ": pinned " + pin.sha256() + ", found " + actual);
        }
        return bytes;
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
