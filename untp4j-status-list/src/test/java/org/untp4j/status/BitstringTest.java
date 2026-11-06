package org.untp4j.status;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BitstringTest {

    /** encodedList of the W3C Bitstring Status List spec example: 16 KiB, all zero. */
    private static final String SPEC_EXAMPLE = "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";

    @Test
    void decodesSpecExample() {
        Bitstring bits = Bitstring.decode(SPEC_EXAMPLE);

        assertThat(bits.size()).isEqualTo(131_072);
        assertThat(bits.toByteArray()).containsOnly(0);
    }

    @Test
    void indexZeroIsMostSignificantBitOfFirstByte() {
        Bitstring bits = Bitstring.empty();
        bits.set(0, true);
        bits.set(15, true);

        byte[] raw = bits.toByteArray();
        assertThat(raw[0]).isEqualTo((byte) 0x80);
        assertThat(raw[1]).isEqualTo((byte) 0x01);
    }

    @Test
    void roundTripsThroughEncoding() {
        Bitstring bits = Bitstring.empty();
        bits.set(42_137, true);
        bits.set(131_071, true);

        Bitstring decoded = Bitstring.decode(bits.encode());

        assertThat(decoded.get(42_137)).isTrue();
        assertThat(decoded.get(131_071)).isTrue();
        assertThat(decoded.get(42_138)).isFalse();
        assertThat(bits.encode()).startsWith("u");
    }

    @Test
    void setFalseClearsBit() {
        Bitstring bits = Bitstring.empty();
        bits.set(7, true);
        bits.set(7, false);

        assertThat(bits.get(7)).isFalse();
    }

    @Test
    void rejectsIndexOutsideList() {
        Bitstring bits = Bitstring.empty();

        assertThatThrownBy(() -> bits.get(131_072)).isInstanceOf(StatusListException.class);
        assertThatThrownBy(() -> bits.get(-1)).isInstanceOf(StatusListException.class);
    }

    @Test
    void rejectsListShorterThanSpecMinimum() throws Exception {
        assertThatThrownBy(() -> Bitstring.decode(encode(new byte[1024])))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("shorter");
    }

    @Test
    void rejectsGzipBomb() throws Exception {
        String bomb = encode(new byte[4 * 1024 * 1024]);

        assertThatThrownBy(() -> Bitstring.decode(bomb, 1024 * 1024))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("exceeds");
    }

    @Test
    void rejectsNonMultibaseValue() {
        assertThatThrownBy(() -> Bitstring.decode("H4sIAAAA"))
                .isInstanceOf(StatusListException.class)
                .hasMessageContaining("multibase");
    }

    @Test
    void rejectsSizeBelowMinimum() {
        assertThatThrownBy(() -> Bitstring.ofSize(8)).isInstanceOf(IllegalArgumentException.class);
    }

    private static String encode(byte[] raw) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(raw);
        }
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
    }
}
