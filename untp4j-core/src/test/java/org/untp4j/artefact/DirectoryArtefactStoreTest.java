package org.untp4j.artefact;

import org.untp4j.CredentialType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DirectoryArtefactStoreTest {

    private static final URI URL = URI.create("https://example.com/schema.json");
    private static final byte[] CONTENT = "{\"type\":\"object\"}".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    @Test
    void servesFileMatchingPin() throws IOException {
        Files.write(dir.resolve("schema.json"), CONTENT);

        byte[] loaded = store("schema.json", DirectoryArtefactStore.sha256(CONTENT)).load(URL);

        assertThat(loaded).isEqualTo(CONTENT);
    }

    @Test
    void rejectsTamperedFile() throws IOException {
        Files.write(dir.resolve("schema.json"), "{\"type\":\"string\"}".getBytes(StandardCharsets.UTF_8));

        DirectoryArtefactStore store = store("schema.json", DirectoryArtefactStore.sha256(CONTENT));

        assertThatThrownBy(() -> store.load(URL))
                .isInstanceOf(ArtefactException.class)
                .hasMessageContaining("SHA-256 mismatch");
    }

    @Test
    void rejectsUnpinnedUrl() throws IOException {
        DirectoryArtefactStore store = store("schema.json", DirectoryArtefactStore.sha256(CONTENT));

        assertThatThrownBy(() -> store.load(URI.create("https://attacker.example/schema.json")))
                .isInstanceOf(ArtefactException.class)
                .hasMessageContaining("not pinned");
    }

    @Test
    void rejectsPinnedPathOutsideDirectory() throws IOException {
        DirectoryArtefactStore store = store("../outside.json", DirectoryArtefactStore.sha256(CONTENT));

        assertThatThrownBy(() -> store.load(URL))
                .isInstanceOf(ArtefactException.class)
                .hasMessageContaining("escapes");
    }

    @Test
    void returnedBytesCannotCorruptCache() throws IOException {
        Files.write(dir.resolve("schema.json"), CONTENT);
        DirectoryArtefactStore store = store("schema.json", DirectoryArtefactStore.sha256(CONTENT));

        store.load(URL)[0] = 'X';

        assertThat(store.load(URL)).isEqualTo(CONTENT);
    }

    @Test
    void bundledLockPinsEverySchema() {
        ArtefactLock lock = ArtefactLock.untp070();

        assertThat(lock.untpVersion()).isEqualTo("0.7.0");
        for (CredentialType type : CredentialType.values()) {
            assertThat(lock.pin(type.schemaUrl())).as(type.name()).isPresent();
        }
    }

    private DirectoryArtefactStore store(String file, String sha256) throws IOException {
        String json = """
                {"untpVersion":"test","artefacts":[{"url":"%s","file":"%s","sha256":"%s"}]}
                """.formatted(URL, file, sha256);
        ArtefactLock lock = ArtefactLock.read(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        return new DirectoryArtefactStore(dir, lock);
    }
}
