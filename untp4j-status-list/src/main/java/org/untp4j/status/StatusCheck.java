package org.untp4j.status;

/**
 * The status of one {@code credentialStatus} entry.
 *
 * @param entry the entry that was checked
 * @param set whether the bit is set, i.e. the credential is revoked or suspended
 */
public record StatusCheck(StatusListEntry entry, boolean set) {

    /** @return {@code true} if this entry marks the credential as revoked */
    public boolean revoked() {
        return set && entry.purpose() == StatusPurpose.REVOCATION;
    }

    /** @return {@code true} if this entry marks the credential as suspended */
    public boolean suspended() {
        return set && entry.purpose() == StatusPurpose.SUSPENSION;
    }
}
