package org.untp4j.did.web;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/** Maps {@code did:web} identifiers to the HTTPS URL of their DID document (did:web method spec §3.2). */
public final class DidWeb {

    private static final String PREFIX = "did:web:";
    private static final Pattern HOST = Pattern.compile(
            "(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*");
    private static final Pattern PORT = Pattern.compile("[1-9][0-9]{0,4}");
    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9._~-]+");

    private DidWeb() {
    }

    /**
     * @param did a {@code did:web} identifier, e.g. {@code did:web:example.com:issuers:acme}
     * @return the DID document URL, e.g. {@code https://example.com/issuers/acme/did.json}
     * @throws IllegalArgumentException if {@code did} is not a well-formed {@code did:web}
     */
    public static URI documentUrl(String did) {
        if (!did.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Not a did:web: " + did);
        }
        List<String> parts = Arrays.asList(did.substring(PREFIX.length()).split(":", -1));
        String authority = authority(parts.get(0), did);
        List<String> path = parts.subList(1, parts.size());
        for (String segment : path) {
            if (!SEGMENT.matcher(segment).matches() || segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Invalid path segment '" + segment + "' in " + did);
            }
        }
        String urlPath = path.isEmpty() ? "/.well-known" : "/" + String.join("/", path);
        return URI.create("https://" + authority + urlPath + "/did.json");
    }

    /**
     * @param hostAndPath host plus optional path, e.g. {@code example.com} or {@code example.com/issuers/acme}
     * @return the matching {@code did:web}
     */
    public static String fromHostAndPath(String hostAndPath) {
        String did = PREFIX + hostAndPath.replace("/", ":");
        documentUrl(did);
        return did;
    }

    private static String authority(String encoded, String did) {
        String host = encoded;
        String port = null;
        int colon = encoded.indexOf("%3A");
        if (colon >= 0) {
            host = encoded.substring(0, colon);
            port = encoded.substring(colon + 3);
            if (!PORT.matcher(port).matches() || Integer.parseInt(port) > 65535) {
                throw new IllegalArgumentException("Invalid port in " + did);
            }
        }
        if (!HOST.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid host in " + did);
        }
        return port == null ? host : host + ":" + port;
    }
}
