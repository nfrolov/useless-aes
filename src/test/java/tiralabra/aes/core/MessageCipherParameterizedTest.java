package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class MessageCipherParameterizedTest {

    @Parameters
    public static Collection<Object[]> data() {
        final Collection<Object[]> data = new ArrayList<Object[]>();
        final byte[] key = new byte [] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            };
        final byte[] nonce = new byte [] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            };

        data.add(new Object[] {
            key,
            nonce,
            new byte[] {
                (byte) 0x80
            },
            new byte[] {
                (byte) 0x47, (byte) 0x32, (byte) 0xbf, (byte) 0xed, (byte) 0x60, (byte) 0x50, (byte) 0xe7, (byte) 0xa1,
                (byte) 0x6d, (byte) 0xbe, (byte) 0x29, (byte) 0xb1, (byte) 0x4b, (byte) 0x7f, (byte) 0x44, (byte) 0xad
            }
        });

        data.add(new Object[] {
            key,
            nonce,
            new byte[] {
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0xb8, (byte) 0x05, (byte) 0xab, (byte) 0x42, (byte) 0x26, (byte) 0x46, (byte) 0x99, (byte) 0x89,
                (byte) 0x8f, (byte) 0xa4, (byte) 0x33, (byte) 0xfc, (byte) 0x0e, (byte) 0xcf, (byte) 0x44, (byte) 0x9b
            }
        });

        data.add(new Object[] {
            key,
            nonce,
            new byte[] {
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            },
            new byte[] {
                (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
                (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34,
                (byte) 0x72, (byte) 0x7c, (byte) 0x67, (byte) 0xc1, (byte) 0x26, (byte) 0x47, (byte) 0x58, (byte) 0x47,
                (byte) 0xa8, (byte) 0x99, (byte) 0x4c, (byte) 0x0e, (byte) 0x82, (byte) 0xfb, (byte) 0x77, (byte) 0x7e,
            }
        });

        data.add(new Object[] {
            key,
            nonce,
            new byte[] {
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
                (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34,
                (byte) 0x7b, (byte) 0x11, (byte) 0x8e, (byte) 0x67, (byte) 0x93, (byte) 0x24, (byte) 0x41, (byte) 0xfe,
                (byte) 0x03, (byte) 0xbe, (byte) 0xda, (byte) 0xde, (byte) 0xc7, (byte) 0xd9, (byte) 0x46, (byte) 0xca,
                (byte) 0x77, (byte) 0xe1, (byte) 0x3d, (byte) 0x2d, (byte) 0x1a, (byte) 0x10, (byte) 0xb7, (byte) 0x44,
                (byte) 0xec, (byte) 0xaf, (byte) 0x4a, (byte) 0xf5, (byte) 0x30, (byte) 0xb9, (byte) 0xd1, (byte) 0x6e
            }
        });


        data.add(new Object[] {
            key,
            nonce,
            new byte[] {
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
                (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34,
                (byte) 0x7b, (byte) 0x11, (byte) 0x8e, (byte) 0x67, (byte) 0x93, (byte) 0x24, (byte) 0x41, (byte) 0xfe,
                (byte) 0x03, (byte) 0xbe, (byte) 0xda, (byte) 0xde, (byte) 0xc7, (byte) 0xd9, (byte) 0x46, (byte) 0xca,
                (byte) 0x25, (byte) 0x94, (byte) 0xb5, (byte) 0xde, (byte) 0x91, (byte) 0xef, (byte) 0xd8, (byte) 0xbd,
                (byte) 0x0d, (byte) 0x14, (byte) 0x4a, (byte) 0x2c, (byte) 0xf9, (byte) 0x48, (byte) 0xee, (byte) 0x4b
            }
        });

        return data;
    }

    private final byte[] key;
    private final byte[] nonce;

    private final byte[] plaintext;
    private final byte[] ciphertext;

    private MessageCipher encrypt;
    private MessageCipher decrypt;

    public MessageCipherParameterizedTest(byte[] key, byte[] nonce, byte[] plaintext, byte[] ciphertext) {
        this.key = key;
        this.nonce = nonce;
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;
    }

    @Before
    public void setUp() throws Exception {
        encrypt = MessageCipher.getEncryptionCipher(key, nonce);
        decrypt = MessageCipher.getDecryptionCipher(key, nonce);
    }

    @Test
    public void testEncrypt() {
        byte[] plaintextCopy, actual;

        plaintextCopy = Arrays.copyOf(plaintext, plaintext.length);
        actual = encrypt.process(plaintext);

        assertThat("input plaintext has been modified", plaintext, is(equalTo(plaintextCopy)));
        assertThat(actual, is(equalTo(ciphertext)));
    }

    @Test
    public void testDecrypt() {
        byte[] ciphertextCopy, actual;

        ciphertextCopy = Arrays.copyOf(ciphertext, ciphertext.length);
        actual = decrypt.process(ciphertext);

        assertThat("input ciphertext has been modified", ciphertext, is(equalTo(ciphertextCopy)));
        assertThat(actual, is(equalTo(plaintext)));
    }

}
