# untp4j

Java SDK for the [UN Transparency Protocol (UNTP)](https://untp.unece.org/): issue and verify
Digital Product Passports and related UNTP credentials as W3C Verifiable Credentials.

> **Status:** early development. Not yet published to Maven Central.
>
> untp4j is an independent project. It is not affiliated with or endorsed by UNECE or UN/CEFACT.

## Scope

| UNTP requirement | untp4j |
|---|---|
| Data model | W3C VCDM 2.0, JSON-LD compacted |
| Securing | `application/vc+jwt` enveloping proof (VC-JOSE-COSE) |
| Identifiers | `did:web` |
| Status | W3C Bitstring Status List |
| UNTP version | 0.7.0 |

## Modules

| Module | Purpose |
|---|---|
| `untp4j-core` | Credential types, pinned UNTP artefacts, JSON schema validation |
| `untp4j-jose` | `vc+jwt` signing and verification, `EnvelopedVerifiableCredential` |
| `untp4j-did-web` | `did:web` URL mapping, DID documents, key resolution |
| `untp4j-status-list` | W3C Bitstring Status List: status list credentials, revocation, status checks |
| `untp4j-demo` | Generates a static demo issuer site (not published) |

More modules (identity resolver, verifier, Spring Boot starter) follow the roadmap.

> UNTP 0.7.0 schemas type `statusListIndex` as a JSON integer, while the W3C spec describes a
> base-10 string. untp4j writes integers so credentials pass the UNTP schema, and accepts both.

## Demo issuer site

```sh
./gradlew :untp4j-demo:run --args="--host-path shlee1223.github.io/untp4j-demo --out build/demo-site"
```

This writes `did.json`, a signed revocation status list and two signed demo DPPs (one revoked) to
`build/demo-site/`, ready for GitHub Pages.
The signing key is created at `~/.untp4j/demo-signing-key.jwk` (mode 600) and never written to the site.

## UNTP artefacts

UNTP schemas, contexts and samples are licensed GPL-3.0 by their publisher, so untp4j does not
redistribute them. Instead it pins the SHA-256 of each published file
(`untp4j-core/src/main/resources/org/untp4j/artefact/untp-0.7.0.lock.json`) and only
accepts bytes that match. Schema validation never fetches anything from the network.

To fetch and verify the artefacts locally:

```sh
./gradlew fetchUntpArtefacts
```

They land in `untp4j-core/build/untp-artefacts/`. If a publisher changes a file at a versioned URL,
the build fails with a SHA-256 mismatch so the change can be reviewed before re-pinning.

## Usage

```java
ArtefactStore store = new DirectoryArtefactStore(Path.of("untp-artefacts"), ArtefactLock.untp070());
SchemaValidator validator = new SchemaValidator(store);

ValidationResult result = validator.validate(credentialJson);
if (!result.isValid()) {
    result.violations().forEach(v -> System.out.println(v.path() + ": " + v.message()));
}
```

## Building

Requires JDK 21.

```sh
./gradlew build
```

## License

[Apache License 2.0](LICENSE)
