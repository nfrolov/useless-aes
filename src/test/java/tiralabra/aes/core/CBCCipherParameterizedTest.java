package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CBCCipherParameterizedTest {

    @Parameters
    public static Collection<Object[]> data() {
        final Collection<Object[]> vectors = new ArrayList<Object[]>();

        vectors.add(new Object[] {
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[][] {{
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },{
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            }},
            new byte[][] {{
                (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
                (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34
            },{
                (byte) 0x7b, (byte) 0x11, (byte) 0x8e, (byte) 0x67, (byte) 0x93, (byte) 0x24, (byte) 0x41, (byte) 0xfe,
                (byte) 0x03, (byte) 0xbe, (byte) 0xda, (byte) 0xde, (byte) 0xc7, (byte) 0xd9, (byte) 0x46, (byte) 0xca
            }}
        });

        return vectors;
    }

    private final byte[][] plaintext, ciphertext;
    private final CBCCipher encrypt, decrypt;

    public CBCCipherParameterizedTest(byte[] nonce, byte[] key, byte[][] plaintext, byte[][] ciphertext) {
        this.encrypt = new CBCCipher(key, true, nonce);
        this.decrypt = new CBCCipher(key, false, nonce);
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;
    }

    @Test
    public void testEncrypt() {
        for (int i = 0; i < plaintext.length; ++i) {
            byte[] out = encrypt.process(plaintext[i]);
            assertThat("Block " + i, out, is(equalTo(ciphertext[i])));
        }
    }

    @Test
    public void testDecrypt() {
        for (int i = 0; i < plaintext.length; ++i) {
            byte[] out = decrypt.process(ciphertext[i]);
            assertThat("Block " + i, out, is(equalTo(plaintext[i])));
        }
    }

}
