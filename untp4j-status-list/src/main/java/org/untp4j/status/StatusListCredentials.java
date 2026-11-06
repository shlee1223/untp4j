package org.untp4j.status;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/** Builds unsecured {@code BitstringStatusListCredential}s, to be signed with {@code VcJwtSigner}. */
public final class StatusListCredentials {

    public static final String TYPE = "BitstringStatusListCredential";

    private StatusListCredentials() {
    }

    /**
     * @param issuerDid issuer of the credentials the list covers; it must also sign the list
     * @param url where the signed list will be published; becomes the credential {@code id}
     * @param purpose purpose of every bit in the list
     * @param bits current status bits
     * @param validFrom when this version of the list takes effect
     * @return the unsecured status list credential
     */
    public static ObjectNode create(String issuerDid, URI url, StatusPurpose purpose, Bitstring bits, Instant validFrom) {
        Objects.requireNonNull(issuerDid, "issuerDid");
        Objects.requireNonNull(url, "url");
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        vc.putArray("@context").add("https://www.w3.org/ns/credentials/v2");
        vc.put("id", url.toString());
        vc.putArray("type").add("VerifiableCredential").add(TYPE);
        vc.put("issuer", issuerDid);
        vc.put("validFrom", validFrom.truncatedTo(ChronoUnit.SECONDS).toString());
        ObjectNode subject = vc.putObject("credentialSubject");
        subject.put("id", url + "#list");
        subject.put("type", "BitstringStatusList");
        subject.put("statusPurpose", purpose.value());
        subject.put("encodedList", bits.encode());
        return vc;
    }
}
