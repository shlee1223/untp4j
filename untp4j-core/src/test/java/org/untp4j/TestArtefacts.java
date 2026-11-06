package org.untp4j;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.untp4j.artefact.ArtefactLock;
import org.untp4j.artefact.DirectoryArtefactStore;

import java.io.IOException;
import java.nio.file.Path;

/** Access to artefacts downloaded by the {@code fetchUntpArtefacts} task. */
public final class TestArtefacts {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TestArtefacts() {
    }

    public static Path dir() {
        String dir = System.getProperty("untp.artefacts.dir");
        if (dir == null) {
            throw new IllegalStateException("Run tests through Gradle: untp.artefacts.dir is not set");
        }
        return Path.of(dir);
    }

    public static DirectoryArtefactStore store() {
        return new DirectoryArtefactStore(dir(), ArtefactLock.untp070());
    }

    public static ObjectNode sample(String name) {
        try {
            return (ObjectNode) MAPPER.readTree(dir().resolve("samples/0.7.0").resolve(name + ".json").toFile());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
