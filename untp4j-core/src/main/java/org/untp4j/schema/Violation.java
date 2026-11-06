package org.untp4j.schema;

/**
 * One schema violation.
 *
 * @param path JSON Pointer-style location of the offending value in the credential
 * @param keyword the JSON Schema keyword that failed, e.g. {@code required}
 * @param message human-readable description
 */
public record Violation(String path, String keyword, String message) {
}
