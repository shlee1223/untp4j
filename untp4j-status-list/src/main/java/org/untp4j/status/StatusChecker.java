package org.untp4j.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.untp4j.did.web.DocumentFetcher;
import org.untp4j.jose.EnvelopedCredential;
import org.untp4j.jose.VcJwt;
import org.untp4j.jose.VcJwtException;
import org.untp4j.jose.VcJwtVerifier;
import org.untp4j.jose.VerifiedCredential;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Checks the {@code credentialStatus} of a verified credential against its Bitstring Status List.
 *
 * <p>The status list credential must be a signed {@code vc+jwt} (enveloped or compact) from the
 * <em>same issuer</em> as the credential, of type {@code BitstringStatusListCredential}, currently
 * valid, with a {@code statusPurpose} matching the entry. Any failure throws: a status that cannot
 * be established is never reported as "not revoked".
 */
public final class StatusChecker {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final DocumentFetcher fetcher;
    private final VcJwtVerifier verifier;
    private final Clock clock;
    private final int maxListBytes;

    /**
     * @param fetcher retrieves status list credentials, e.g. an {@code HttpsDocumentFetcher}
     * @param verifier verifies the status list credential's signature
     */
    public StatusChecker(DocumentFetcher fetcher, VcJwtVerifier verifier) {
        this(fetcher, verifier, Clock.systemUTC(), Bitstring.DEFAULT_MAX_BYTES);
    }

    public StatusChecker(DocumentFetcher fetcher, VcJwtVerifier verifier, Clock clock, int maxListBytes) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxListBytes = maxListBytes;
    }

    /**
     * @param credential a credential whose signature has already been verified
     * @return one result per {@code credentialStatus} entry; empty if the credential has none
     * @throws StatusListException if any status cannot be established
     */
    public List<StatusCheck> check(JsonNode credential) {
        String issuer = VcJwt.issuerId(credential)
                .orElseThrow(() -> new StatusListException("Credential has no issuer id"));
        JsonNode status = credential.path("credentialStatus");
        List<JsonNode> entries = new ArrayList<>();
        if (status.isArray()) {
            status.forEach(entries::add);
        } else if (status.isObject()) {
            entries.add(status);
        } else if (!status.isMissingNode()) {
            throw new StatusListException("credentialStatus must be an object or array");
        }
        List<StatusCheck> results = new ArrayList<>();
        for (JsonNode node : entries) {
            StatusListEntry entry = StatusListEntry.parse(node);
            results.add(new StatusCheck(entry, loadList(entry, issuer).get(entry.index())));
        }
        return results;
    }

    private Bitstring loadList(StatusListEntry entry, String issuer) {
        URI url = entry.statusListCredential();
        String jwt;
        try {
            String body = new String(fetcher.fetch(url), java.nio.charset.StandardCharsets.UTF_8).trim();
            jwt = body.startsWith("{") ? EnvelopedCredential.unwrap(MAPPER.readTree(body)) : body;
        } catch (IOException | VcJwtException e) {
            throw new StatusListException("Cannot load status list " + url + ": " + e.getMessage(), e);
        }

        VerifiedCredential verified;
        try {
            verified = verifier.verify(jwt);
        } catch (VcJwtException e) {
            throw new StatusListException("Status list " + url + " failed verification: " + e.getMessage(), e);
        }
        JsonNode list = verified.credential();

        if (!url.toString().equals(list.path("id").asText())) {
            throw new StatusListException("Status list id " + list.path("id").asText() + " does not match " + url);
        }
        if (!hasType(list, StatusListCredentials.TYPE)) {
            throw new StatusListException("Not a " + StatusListCredentials.TYPE + ": " + url);
        }
        String listIssuer = VcJwt.issuerId(list).orElse("");
        if (!issuer.equals(listIssuer)) {
            throw new StatusListException("Status list issuer " + listIssuer + " differs from credential issuer " + issuer);
        }
        checkValidity(list, url);
        JsonNode subject = list.path("credentialSubject");
        if (!entry.purpose().value().equals(subject.path("statusPurpose").asText())) {
            throw new StatusListException("Status list purpose " + subject.path("statusPurpose").asText()
                    + " does not match entry purpose " + entry.purpose().value());
        }
        return Bitstring.decode(subject.path("encodedList").asText(null), maxListBytes);
    }

    private void checkValidity(JsonNode list, URI url) {
        Instant now = clock.instant();
        try {
            if (list.hasNonNull("validFrom") && now.isBefore(Instant.parse(list.get("validFrom").asText()))) {
                throw new StatusListException("Status list " + url + " is not yet valid");
            }
            if (list.hasNonNull("validUntil") && !now.isBefore(Instant.parse(list.get("validUntil").asText()))) {
                throw new StatusListException("Status list " + url + " has expired");
            }
        } catch (DateTimeParseException e) {
            throw new StatusListException("Status list " + url + " has an unreadable validity date", e);
        }
    }

    private static boolean hasType(JsonNode node, String type) {
        JsonNode types = node.path("type");
        if (types.isTextual()) {
            return type.equals(types.asText());
        }
        for (JsonNode t : types) {
            if (type.equals(t.asText())) {
                return true;
            }
        }
        return false;
    }
}
