package org.untp4j.status;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * A W3C Bitstring Status List bitstring (one bit per credential, {@code statusSize} 1).
 * Index 0 is the most significant bit of the first byte.
 */
public final class Bitstring {

    /** Minimum uncompressed size required by the spec: 16 KiB, i.e. 131,072 entries. */
    public static final int MIN_BYTES = 16 * 1024;

    /** Default upper bound on the decompressed size accepted when decoding (guards against gzip bombs). */
    public static final int DEFAULT_MAX_BYTES = 16 * 1024 * 1024;

    private final byte[] bits;

    private Bitstring(byte[] bits) {
        this.bits = bits;
    }

    /** @return an all-zero bitstring of the minimum size */
    public static Bitstring empty() {
        return new Bitstring(new byte[MIN_BYTES]);
    }

    /**
     * @param sizeInBits number of entries; a multiple of 8 and at least 131,072
     * @return an all-zero bitstring
     */
    public static Bitstring ofSize(long sizeInBits) {
        if (sizeInBits % 8 != 0 || sizeInBits < MIN_BYTES * 8L || sizeInBits / 8 > DEFAULT_MAX_BYTES) {
            throw new IllegalArgumentException("Size must be a multiple of 8 between "
                    + MIN_BYTES * 8L + " and " + DEFAULT_MAX_BYTES * 8L + " bits");
        }
        return new Bitstring(new byte[(int) (sizeInBits / 8)]);
    }

    /**
     * Decodes an {@code encodedList}: multibase base64url (prefix {@code u}) of a GZIP-compressed bitstring.
     *
     * @param encodedList the encoded list
     * @param maxBytes largest decompressed size accepted
     * @return the bitstring
     * @throws StatusListException if the value is malformed, too short or too large
     */
    public static Bitstring decode(String encodedList, int maxBytes) {
        if (encodedList == null || !encodedList.startsWith("u")) {
            throw new StatusListException("encodedList must be multibase base64url (prefix 'u')");
        }
        byte[] compressed;
        try {
            compressed = Base64.getUrlDecoder().decode(encodedList.substring(1));
        } catch (IllegalArgumentException e) {
            throw new StatusListException("encodedList is not valid base64url", e);
        }
        byte[] bits;
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            bits = in.readNBytes(maxBytes + 1);
        } catch (IOException e) {
            throw new StatusListException("encodedList is not valid GZIP", e);
        }
        if (bits.length > maxBytes) {
            throw new StatusListException("Status list exceeds " + maxBytes + " bytes");
        }
        if (bits.length < MIN_BYTES) {
            throw new StatusListException("Status list is shorter than the required " + MIN_BYTES + " bytes");
        }
        return new Bitstring(bits);
    }

    /**
     * @param encodedList the encoded list
     * @return the bitstring, limited to {@link #DEFAULT_MAX_BYTES}
     */
    public static Bitstring decode(String encodedList) {
        return decode(encodedList, DEFAULT_MAX_BYTES);
    }

    /** @return the {@code encodedList} value */
    public String encode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(bits);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
    }

    /** @return number of entries */
    public long size() {
        return bits.length * 8L;
    }

    /**
     * @param index entry index
     * @return {@code true} if the bit is set
     * @throws StatusListException if {@code index} is outside the list
     */
    public boolean get(long index) {
        checkIndex(index);
        return (bits[(int) (index / 8)] & (0x80 >>> (index % 8))) != 0;
    }

    /**
     * @param index entry index
     * @param value new bit value
     */
    public void set(long index, boolean value) {
        checkIndex(index);
        int i = (int) (index / 8);
        int mask = 0x80 >>> (index % 8);
        bits[i] = (byte) (value ? bits[i] | mask : bits[i] & ~mask);
    }

    /** @return a copy of the raw bytes */
    public byte[] toByteArray() {
        return Arrays.copyOf(bits, bits.length);
    }

    private void checkIndex(long index) {
        if (index < 0 || index >= size()) {
            throw new StatusListException("Index " + index + " is outside the status list (size " + size() + ")");
        }
    }
}
