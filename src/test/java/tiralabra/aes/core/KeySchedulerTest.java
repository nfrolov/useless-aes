package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.Arrays;

import org.junit.Before;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class KeySchedulerTest {

    private KeyScheduler scheduler;

    /**
     * Test vectors for the AES key schedule.
     * Source: http://www.samiam.org/key-schedule.html
     */
    @DataPoints
    public static final byte[][] vectors = new byte[][] {{
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x62, (byte) 0x63, (byte) 0x63, (byte) 0x63, (byte) 0x62, (byte) 0x63, (byte) 0x63, (byte) 0x63,
        (byte) 0x62, (byte) 0x63, (byte) 0x63, (byte) 0x63, (byte) 0x62, (byte) 0x63, (byte) 0x63, (byte) 0x63,
        (byte) 0x9b, (byte) 0x98, (byte) 0x98, (byte) 0xc9, (byte) 0xf9, (byte) 0xfb, (byte) 0xfb, (byte) 0xaa,
        (byte) 0x9b, (byte) 0x98, (byte) 0x98, (byte) 0xc9, (byte) 0xf9, (byte) 0xfb, (byte) 0xfb, (byte) 0xaa,
        (byte) 0x90, (byte) 0x97, (byte) 0x34, (byte) 0x50, (byte) 0x69, (byte) 0x6c, (byte) 0xcf, (byte) 0xfa,
        (byte) 0xf2, (byte) 0xf4, (byte) 0x57, (byte) 0x33, (byte) 0x0b, (byte) 0x0f, (byte) 0xac, (byte) 0x99,
        (byte) 0xee, (byte) 0x06, (byte) 0xda, (byte) 0x7b, (byte) 0x87, (byte) 0x6a, (byte) 0x15, (byte) 0x81,
        (byte) 0x75, (byte) 0x9e, (byte) 0x42, (byte) 0xb2, (byte) 0x7e, (byte) 0x91, (byte) 0xee, (byte) 0x2b,
        (byte) 0x7f, (byte) 0x2e, (byte) 0x2b, (byte) 0x88, (byte) 0xf8, (byte) 0x44, (byte) 0x3e, (byte) 0x09,
        (byte) 0x8d, (byte) 0xda, (byte) 0x7c, (byte) 0xbb, (byte) 0xf3, (byte) 0x4b, (byte) 0x92, (byte) 0x90,
        (byte) 0xec, (byte) 0x61, (byte) 0x4b, (byte) 0x85, (byte) 0x14, (byte) 0x25, (byte) 0x75, (byte) 0x8c,
        (byte) 0x99, (byte) 0xff, (byte) 0x09, (byte) 0x37, (byte) 0x6a, (byte) 0xb4, (byte) 0x9b, (byte) 0xa7,
        (byte) 0x21, (byte) 0x75, (byte) 0x17, (byte) 0x87, (byte) 0x35, (byte) 0x50, (byte) 0x62, (byte) 0x0b,
        (byte) 0xac, (byte) 0xaf, (byte) 0x6b, (byte) 0x3c, (byte) 0xc6, (byte) 0x1b, (byte) 0xf0, (byte) 0x9b,
        (byte) 0x0e, (byte) 0xf9, (byte) 0x03, (byte) 0x33, (byte) 0x3b, (byte) 0xa9, (byte) 0x61, (byte) 0x38,
        (byte) 0x97, (byte) 0x06, (byte) 0x0a, (byte) 0x04, (byte) 0x51, (byte) 0x1d, (byte) 0xfa, (byte) 0x9f,
        (byte) 0xb1, (byte) 0xd4, (byte) 0xd8, (byte) 0xe2, (byte) 0x8a, (byte) 0x7d, (byte) 0xb9, (byte) 0xda,
        (byte) 0x1d, (byte) 0x7b, (byte) 0xb3, (byte) 0xde, (byte) 0x4c, (byte) 0x66, (byte) 0x49, (byte) 0x41,
        (byte) 0xb4, (byte) 0xef, (byte) 0x5b, (byte) 0xcb, (byte) 0x3e, (byte) 0x92, (byte) 0xe2, (byte) 0x11,
        (byte) 0x23, (byte) 0xe9, (byte) 0x51, (byte) 0xcf, (byte) 0x6f, (byte) 0x8f, (byte) 0x18, (byte) 0x8e,
    }, {
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
        (byte) 0xe8, (byte) 0xe9, (byte) 0xe9, (byte) 0xe9, (byte) 0x17, (byte) 0x16, (byte) 0x16, (byte) 0x16,
        (byte) 0xe8, (byte) 0xe9, (byte) 0xe9, (byte) 0xe9, (byte) 0x17, (byte) 0x16, (byte) 0x16, (byte) 0x16,
        (byte) 0xad, (byte) 0xae, (byte) 0xae, (byte) 0x19, (byte) 0xba, (byte) 0xb8, (byte) 0xb8, (byte) 0x0f,
        (byte) 0x52, (byte) 0x51, (byte) 0x51, (byte) 0xe6, (byte) 0x45, (byte) 0x47, (byte) 0x47, (byte) 0xf0,
        (byte) 0x09, (byte) 0x0e, (byte) 0x22, (byte) 0x77, (byte) 0xb3, (byte) 0xb6, (byte) 0x9a, (byte) 0x78,
        (byte) 0xe1, (byte) 0xe7, (byte) 0xcb, (byte) 0x9e, (byte) 0xa4, (byte) 0xa0, (byte) 0x8c, (byte) 0x6e,
        (byte) 0xe1, (byte) 0x6a, (byte) 0xbd, (byte) 0x3e, (byte) 0x52, (byte) 0xdc, (byte) 0x27, (byte) 0x46,
        (byte) 0xb3, (byte) 0x3b, (byte) 0xec, (byte) 0xd8, (byte) 0x17, (byte) 0x9b, (byte) 0x60, (byte) 0xb6,
        (byte) 0xe5, (byte) 0xba, (byte) 0xf3, (byte) 0xce, (byte) 0xb7, (byte) 0x66, (byte) 0xd4, (byte) 0x88,
        (byte) 0x04, (byte) 0x5d, (byte) 0x38, (byte) 0x50, (byte) 0x13, (byte) 0xc6, (byte) 0x58, (byte) 0xe6,
        (byte) 0x71, (byte) 0xd0, (byte) 0x7d, (byte) 0xb3, (byte) 0xc6, (byte) 0xb6, (byte) 0xa9, (byte) 0x3b,
        (byte) 0xc2, (byte) 0xeb, (byte) 0x91, (byte) 0x6b, (byte) 0xd1, (byte) 0x2d, (byte) 0xc9, (byte) 0x8d,
        (byte) 0xe9, (byte) 0x0d, (byte) 0x20, (byte) 0x8d, (byte) 0x2f, (byte) 0xbb, (byte) 0x89, (byte) 0xb6,
        (byte) 0xed, (byte) 0x50, (byte) 0x18, (byte) 0xdd, (byte) 0x3c, (byte) 0x7d, (byte) 0xd1, (byte) 0x50,
        (byte) 0x96, (byte) 0x33, (byte) 0x73, (byte) 0x66, (byte) 0xb9, (byte) 0x88, (byte) 0xfa, (byte) 0xd0,
        (byte) 0x54, (byte) 0xd8, (byte) 0xe2, (byte) 0x0d, (byte) 0x68, (byte) 0xa5, (byte) 0x33, (byte) 0x5d,
        (byte) 0x8b, (byte) 0xf0, (byte) 0x3f, (byte) 0x23, (byte) 0x32, (byte) 0x78, (byte) 0xc5, (byte) 0xf3,
        (byte) 0x66, (byte) 0xa0, (byte) 0x27, (byte) 0xfe, (byte) 0x0e, (byte) 0x05, (byte) 0x14, (byte) 0xa3,
        (byte) 0xd6, (byte) 0x0a, (byte) 0x35, (byte) 0x88, (byte) 0xe4, (byte) 0x72, (byte) 0xf0, (byte) 0x7b,
        (byte) 0x82, (byte) 0xd2, (byte) 0xd7, (byte) 0x85, (byte) 0x8c, (byte) 0xd7, (byte) 0xc3, (byte) 0x26,
    }, {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
        (byte) 0xd6, (byte) 0xaa, (byte) 0x74, (byte) 0xfd, (byte) 0xd2, (byte) 0xaf, (byte) 0x72, (byte) 0xfa,
        (byte) 0xda, (byte) 0xa6, (byte) 0x78, (byte) 0xf1, (byte) 0xd6, (byte) 0xab, (byte) 0x76, (byte) 0xfe,
        (byte) 0xb6, (byte) 0x92, (byte) 0xcf, (byte) 0x0b, (byte) 0x64, (byte) 0x3d, (byte) 0xbd, (byte) 0xf1,
        (byte) 0xbe, (byte) 0x9b, (byte) 0xc5, (byte) 0x00, (byte) 0x68, (byte) 0x30, (byte) 0xb3, (byte) 0xfe,
        (byte) 0xb6, (byte) 0xff, (byte) 0x74, (byte) 0x4e, (byte) 0xd2, (byte) 0xc2, (byte) 0xc9, (byte) 0xbf,
        (byte) 0x6c, (byte) 0x59, (byte) 0x0c, (byte) 0xbf, (byte) 0x04, (byte) 0x69, (byte) 0xbf, (byte) 0x41,
        (byte) 0x47, (byte) 0xf7, (byte) 0xf7, (byte) 0xbc, (byte) 0x95, (byte) 0x35, (byte) 0x3e, (byte) 0x03,
        (byte) 0xf9, (byte) 0x6c, (byte) 0x32, (byte) 0xbc, (byte) 0xfd, (byte) 0x05, (byte) 0x8d, (byte) 0xfd,
        (byte) 0x3c, (byte) 0xaa, (byte) 0xa3, (byte) 0xe8, (byte) 0xa9, (byte) 0x9f, (byte) 0x9d, (byte) 0xeb,
        (byte) 0x50, (byte) 0xf3, (byte) 0xaf, (byte) 0x57, (byte) 0xad, (byte) 0xf6, (byte) 0x22, (byte) 0xaa,
        (byte) 0x5e, (byte) 0x39, (byte) 0x0f, (byte) 0x7d, (byte) 0xf7, (byte) 0xa6, (byte) 0x92, (byte) 0x96,
        (byte) 0xa7, (byte) 0x55, (byte) 0x3d, (byte) 0xc1, (byte) 0x0a, (byte) 0xa3, (byte) 0x1f, (byte) 0x6b,
        (byte) 0x14, (byte) 0xf9, (byte) 0x70, (byte) 0x1a, (byte) 0xe3, (byte) 0x5f, (byte) 0xe2, (byte) 0x8c,
        (byte) 0x44, (byte) 0x0a, (byte) 0xdf, (byte) 0x4d, (byte) 0x4e, (byte) 0xa9, (byte) 0xc0, (byte) 0x26,
        (byte) 0x47, (byte) 0x43, (byte) 0x87, (byte) 0x35, (byte) 0xa4, (byte) 0x1c, (byte) 0x65, (byte) 0xb9,
        (byte) 0xe0, (byte) 0x16, (byte) 0xba, (byte) 0xf4, (byte) 0xae, (byte) 0xbf, (byte) 0x7a, (byte) 0xd2,
        (byte) 0x54, (byte) 0x99, (byte) 0x32, (byte) 0xd1, (byte) 0xf0, (byte) 0x85, (byte) 0x57, (byte) 0x68,
        (byte) 0x10, (byte) 0x93, (byte) 0xed, (byte) 0x9c, (byte) 0xbe, (byte) 0x2c, (byte) 0x97, (byte) 0x4e,
        (byte) 0x13, (byte) 0x11, (byte) 0x1d, (byte) 0x7f, (byte) 0xe3, (byte) 0x94, (byte) 0x4a, (byte) 0x17,
        (byte) 0xf3, (byte) 0x07, (byte) 0xa7, (byte) 0x8b, (byte) 0x4d, (byte) 0x2b, (byte) 0x30, (byte) 0xc5,
    }, {
        (byte) 0x69, (byte) 0x20, (byte) 0xe2, (byte) 0x99, (byte) 0xa5, (byte) 0x20, (byte) 0x2a, (byte) 0x6d,
        (byte) 0x65, (byte) 0x6e, (byte) 0x63, (byte) 0x68, (byte) 0x69, (byte) 0x74, (byte) 0x6f, (byte) 0x2a,
        (byte) 0xfa, (byte) 0x88, (byte) 0x07, (byte) 0x60, (byte) 0x5f, (byte) 0xa8, (byte) 0x2d, (byte) 0x0d,
        (byte) 0x3a, (byte) 0xc6, (byte) 0x4e, (byte) 0x65, (byte) 0x53, (byte) 0xb2, (byte) 0x21, (byte) 0x4f,
        (byte) 0xcf, (byte) 0x75, (byte) 0x83, (byte) 0x8d, (byte) 0x90, (byte) 0xdd, (byte) 0xae, (byte) 0x80,
        (byte) 0xaa, (byte) 0x1b, (byte) 0xe0, (byte) 0xe5, (byte) 0xf9, (byte) 0xa9, (byte) 0xc1, (byte) 0xaa,
        (byte) 0x18, (byte) 0x0d, (byte) 0x2f, (byte) 0x14, (byte) 0x88, (byte) 0xd0, (byte) 0x81, (byte) 0x94,
        (byte) 0x22, (byte) 0xcb, (byte) 0x61, (byte) 0x71, (byte) 0xdb, (byte) 0x62, (byte) 0xa0, (byte) 0xdb,
        (byte) 0xba, (byte) 0xed, (byte) 0x96, (byte) 0xad, (byte) 0x32, (byte) 0x3d, (byte) 0x17, (byte) 0x39,
        (byte) 0x10, (byte) 0xf6, (byte) 0x76, (byte) 0x48, (byte) 0xcb, (byte) 0x94, (byte) 0xd6, (byte) 0x93,
        (byte) 0x88, (byte) 0x1b, (byte) 0x4a, (byte) 0xb2, (byte) 0xba, (byte) 0x26, (byte) 0x5d, (byte) 0x8b,
        (byte) 0xaa, (byte) 0xd0, (byte) 0x2b, (byte) 0xc3, (byte) 0x61, (byte) 0x44, (byte) 0xfd, (byte) 0x50,
        (byte) 0xb3, (byte) 0x4f, (byte) 0x19, (byte) 0x5d, (byte) 0x09, (byte) 0x69, (byte) 0x44, (byte) 0xd6,
        (byte) 0xa3, (byte) 0xb9, (byte) 0x6f, (byte) 0x15, (byte) 0xc2, (byte) 0xfd, (byte) 0x92, (byte) 0x45,
        (byte) 0xa7, (byte) 0x00, (byte) 0x77, (byte) 0x78, (byte) 0xae, (byte) 0x69, (byte) 0x33, (byte) 0xae,
        (byte) 0x0d, (byte) 0xd0, (byte) 0x5c, (byte) 0xbb, (byte) 0xcf, (byte) 0x2d, (byte) 0xce, (byte) 0xfe,
        (byte) 0xff, (byte) 0x8b, (byte) 0xcc, (byte) 0xf2, (byte) 0x51, (byte) 0xe2, (byte) 0xff, (byte) 0x5c,
        (byte) 0x5c, (byte) 0x32, (byte) 0xa3, (byte) 0xe7, (byte) 0x93, (byte) 0x1f, (byte) 0x6d, (byte) 0x19,
        (byte) 0x24, (byte) 0xb7, (byte) 0x18, (byte) 0x2e, (byte) 0x75, (byte) 0x55, (byte) 0xe7, (byte) 0x72,
        (byte) 0x29, (byte) 0x67, (byte) 0x44, (byte) 0x95, (byte) 0xba, (byte) 0x78, (byte) 0x29, (byte) 0x8c,
        (byte) 0xae, (byte) 0x12, (byte) 0x7c, (byte) 0xda, (byte) 0xdb, (byte) 0x47, (byte) 0x9b, (byte) 0xa8,
        (byte) 0xf2, (byte) 0x20, (byte) 0xdf, (byte) 0x3d, (byte) 0x48, (byte) 0x58, (byte) 0xf6, (byte) 0xb1,
    }};

    @Before
    public void setUp() throws Exception {
        scheduler = new KeyScheduler();
    }

    @Theory
    public void testSchedule(final byte[] vector) {
        final byte[] key;
        final int[] out;

        key = Arrays.copyOfRange(vector, 0, 16); // block of first 16 bytes is a key
        out = scheduler.schedule(key);

        assertThat(out, is(not(nullValue())));
        assertThat("should return 11 round keys of 16 bytes each", out.length, is(44));

        for (int i = 0; i < (vector.length / 16); ++i) {
            final int[] roundKey = Arrays.copyOfRange(out, 4 * i, 4 * i + 4), expectedRoundKey = packRoundKey(vector, i);
            assertThat("round key " + (i + 1), roundKey, is(equalTo(expectedRoundKey)));
        }
    }

    private static int[] packRoundKey(final byte[] bs, final int n) {
        final int[] words = new int[4];
        final int offset = 16 * n;

        for (int i = 0; i < words.length; i++) {
            words[i] = pack(bs[offset + i * 4], bs[offset + i * 4 + 1], bs[offset + i * 4 + 2], bs[offset + i * 4 + 3]);
        }

        return words;
    }

    private static int pack(final byte a, final byte b, final byte c, final byte d) {
        return (a & 0xff) | ((b & 0xff) << 8) | ((c & 0xff) << 16) | ((d & 0xff) << 24);
    }

}
