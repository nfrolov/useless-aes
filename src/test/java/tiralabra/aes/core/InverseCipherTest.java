package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class InverseCipherTest {

    private InverseCipher cipher;

    /**
     * Few test vectors for the AES encryption.
     * Source: http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
     */
    @DataPoints
    public static final byte[][][] vectors = new byte[][][] {{
        {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },{
            (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },{
            (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
            (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34
        }
    },{
        {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },{
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        },{
            (byte) 0x3f, (byte) 0x5b, (byte) 0x8c, (byte) 0xc9, (byte) 0xea, (byte) 0x85, (byte) 0x5a, (byte) 0x0a,
            (byte) 0xfa, (byte) 0x73, (byte) 0x47, (byte) 0xd2, (byte) 0x3e, (byte) 0x8d, (byte) 0x66, (byte) 0x4e
        }
    },{
        {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },{
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },{
            (byte) 0xf8, (byte) 0x07, (byte) 0xc3, (byte) 0xe7, (byte) 0x98, (byte) 0x5f, (byte) 0xe0, (byte) 0xf5,
            (byte) 0xa5, (byte) 0x0e, (byte) 0x2c, (byte) 0xdb, (byte) 0x25, (byte) 0xc5, (byte) 0x10, (byte) 0x9e
        }
    }};

    @Before
    public void setUp() throws Exception {
    }

    @Theory
    public void testDecrypt(final byte[][] vector) {
        final byte[] key = vector[0], expectedPlaintext = vector[1], ciphertext = vector[2];
        final byte[] plaintext;

        cipher = new InverseCipher(key);
        plaintext = cipher.decrypt(ciphertext);

        assertThat(plaintext, is(equalTo(expectedPlaintext)));
    }

}
