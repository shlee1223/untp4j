package org.untp4j.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.untp4j.artefact.ArtefactLock;
import org.untp4j.artefact.DirectoryArtefactStore;
import org.untp4j.did.web.DidDocuments;
import org.untp4j.did.web.DidWeb;
import org.untp4j.did.web.DidWebResolver;
import org.untp4j.jose.EnvelopedCredential;
import org.untp4j.jose.VcJwtSigner;
import org.untp4j.jose.VcJwtVerifier;
import org.untp4j.schema.SchemaValidator;
import org.untp4j.schema.ValidationResult;
import org.untp4j.status.Bitstring;
import org.untp4j.status.StatusCheck;
import org.untp4j.status.StatusChecker;
import org.untp4j.status.StatusListCredentials;
import org.untp4j.status.StatusListEntry;
import org.untp4j.status.StatusPurpose;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates a static did:web issuer site: a DID document, a signed revocation status list and two
 * signed demo Digital Product Passports (one active, one revoked), ready to publish on GitHub Pages.
 *
 * <pre>
 * ./gradlew :untp4j-demo:run --args="--host-path shlee1223.github.io/untp4j-demo --out build/demo-site"
 * </pre>
 *
 * The signing key is kept outside the site directory and is never written to it.
 */
public final class GenerateDemoSite {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final String STATUS_LIST_PATH = "status/revocation/1.json";

    /** Demo passports: name, status list index (spread out, as the spec recommends), revoked. */
    private record Passport(String name, long index, boolean revoked) {
        String path() {
            return "credentials/dpp/" + name + ".json";
        }
    }

    private static final List<Passport> PASSPORTS = List.of(
            new Passport("battery-001", 42_137, false),
            new Passport("battery-002", 90_210, true));

    private GenerateDemoSite() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> opts = parse(args);
        String hostPath = opts.getOrDefault("host-path", "shlee1223.github.io/untp4j-demo");
        Path out = Path.of(opts.getOrDefault("out", "build/demo-site")).toAbsolutePath().normalize();
        Path keyFile = Path.of(opts.getOrDefault("key",
                System.getProperty("user.home") + "/.untp4j/demo-signing-key.jwk")).toAbsolutePath().normalize();
        Path artefacts = Path.of(require(System.getProperty("untp.artefacts.dir"), "untp.artefacts.dir"));

        if (keyFile.startsWith(out)) {
            throw new IllegalArgumentException("Signing key must not live inside the site directory");
        }

        String did = DidWeb.fromHostAndPath(hostPath);
        String base = "https://" + hostPath;
        ECKey key = loadOrCreateKey(keyFile, did + "#key-1");
        VcJwtSigner signer = VcJwtSigner.es256(key);
        SchemaValidator schemas = new SchemaValidator(new DirectoryArtefactStore(artefacts, ArtefactLock.untp070()));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        URI statusListUrl = URI.create(base + "/" + STATUS_LIST_PATH);

        // Everything to publish, keyed by site path.
        Map<String, byte[]> site = new LinkedHashMap<>();
        site.put("did.json", MAPPER.writeValueAsBytes(DidDocuments.withAssertionKey(did, key.toPublicJWK())));

        Bitstring revocations = Bitstring.empty();
        for (Passport p : PASSPORTS) {
            revocations.set(p.index(), p.revoked());
        }
        String statusJwt = signer.sign(StatusListCredentials.create(did, statusListUrl,
                StatusPurpose.REVOCATION, revocations, now));
        site.put(STATUS_LIST_PATH, MAPPER.writeValueAsBytes(EnvelopedCredential.wrap(statusJwt)));

        for (Passport p : PASSPORTS) {
            ObjectNode credential = (ObjectNode) credential(Map.of(
                    "{{DID}}", did,
                    "{{BASE}}", base,
                    "{{NAME}}", p.name(),
                    "{{VALID_FROM}}", now.toString(),
                    "{{VALID_UNTIL}}", now.plus(365, ChronoUnit.DAYS).toString()));
            credential.set("credentialStatus",
                    new StatusListEntry(statusListUrl, p.index(), StatusPurpose.REVOCATION).toJson());

            ValidationResult schema = schemas.validate(credential);
            if (!schema.isValid()) {
                schema.violations().forEach(v -> System.err.println("  " + v.path() + ": " + v.message()));
                throw new IllegalStateException(p.name() + " does not match the UNTP schema");
            }
            site.put(p.path(), MAPPER.writeValueAsBytes(EnvelopedCredential.wrap(signer.sign(credential))));
        }

        selfCheck(did, base, site);

        Files.createDirectories(out);
        for (Map.Entry<String, byte[]> e : site.entrySet()) {
            write(out.resolve(e.getKey()), e.getValue());
        }
        write(out.resolve(".nojekyll"), new byte[0]);
        write(out.resolve("index.html"), index(did).getBytes(StandardCharsets.UTF_8));

        System.out.println("DID:         " + did);
        System.out.println("Status list: " + statusListUrl);
        for (Passport p : PASSPORTS) {
            System.out.println("Passport:    " + base + "/" + p.path() + (p.revoked() ? "  (revoked)" : ""));
        }
        System.out.println("Site:        " + out);
    }

    /** Verifies the exact bytes about to be published, serving every URL from the in-memory site. */
    private static void selfCheck(String did, String base, Map<String, byte[]> site) throws Exception {
        Map<URI, byte[]> byUrl = new HashMap<>();
        site.forEach((path, bytes) -> byUrl.put(URI.create(base + "/" + path), bytes));
        byUrl.put(DidWeb.documentUrl(did), site.get("did.json"));
        org.untp4j.did.web.DocumentFetcher local = url -> {
            byte[] bytes = byUrl.get(url);
            if (bytes == null) {
                throw new IOException("Not part of the site: " + url);
            }
            return bytes;
        };
        VcJwtVerifier verifier = new VcJwtVerifier(new DidWebResolver(local));
        StatusChecker statuses = new StatusChecker(local, verifier);

        for (Passport p : PASSPORTS) {
            JsonNode enveloped = MAPPER.readTree(site.get(p.path()));
            JsonNode credential = verifier.verify(EnvelopedCredential.unwrap(enveloped)).credential();
            List<StatusCheck> checks = statuses.check(credential);
            boolean revoked = checks.stream().anyMatch(StatusCheck::revoked);
            if (checks.size() != 1 || revoked != p.revoked()) {
                throw new IllegalStateException(p.name() + ": expected revoked=" + p.revoked() + " but was " + revoked);
            }
        }
    }

    private static ECKey loadOrCreateKey(Path file, String kid) throws Exception {
        if (Files.exists(file)) {
            ECKey key = ECKey.parse(Files.readString(file));
            if (!kid.equals(key.getKeyID()) || !key.isPrivate()) {
                throw new IllegalStateException("Key in " + file + " is not a private key with kid " + kid);
            }
            return key;
        }
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        Files.createDirectories(file.getParent(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(file, key.toJSONString());
        System.out.println("Created signing key " + file);
        return key;
    }

    private static JsonNode credential(Map<String, String> values) throws IOException {
        String template;
        try (InputStream in = GenerateDemoSite.class.getResourceAsStream("dpp-battery.json")) {
            template = new String(require(in, "dpp-battery.json").readAllBytes(), StandardCharsets.UTF_8);
        }
        for (Map.Entry<String, String> e : values.entrySet()) {
            template = template.replace(e.getKey(), e.getValue());
        }
        return MAPPER.readTree(template);
    }

    private static String index(String did) {
        StringBuilder items = new StringBuilder();
        for (Passport p : PASSPORTS) {
            items.append("  <li>Digital Product Passport: <a href=\"").append(p.path()).append("\">")
                    .append(p.name()).append("</a>").append(p.revoked() ? " (revoked)" : "").append("</li>\n");
        }
        return """
                <!doctype html>
                <html lang="en">
                <meta charset="utf-8">
                <title>untp4j demo issuer</title>
                <h1>untp4j demo issuer</h1>
                <p>Fictional issuer used to test <a href="https://github.com/shlee1223/untp4j">untp4j</a>
                against UNTP tooling. Not a real company or product.</p>
                <ul>
                  <li>DID: <code>%s</code> (<a href="did.json">did.json</a>)</li>
                  <li>Revocation status list: <a href="%s">%s</a></li>
                %s</ul>
                </html>
                """.formatted(did, STATUS_LIST_PATH, STATUS_LIST_PATH, items);
    }

    private static void write(Path file, byte[] bytes) throws IOException {
        Files.createDirectories(file.getParent());
        Files.write(file, bytes);
    }

    private static Map<String, String> parse(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 0; i < args.length; i += 2) {
            if (!args[i].startsWith("--") || i + 1 >= args.length) {
                throw new IllegalArgumentException("Usage: --host-path <host/path> --out <dir> [--key <file>]");
            }
            opts.put(args[i].substring(2), args[i + 1]);
        }
        return opts;
    }

    private static <T> T require(T value, String name) {
        if (value == null) {
            throw new IllegalStateException("Missing " + name);
        }
        return value;
    }
}
