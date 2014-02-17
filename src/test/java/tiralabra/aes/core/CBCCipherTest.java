package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CBCCipherTest {

    private final byte[][] vector = new byte[][] {{
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    },{
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    },{
        (byte) 0x3a, (byte) 0xd7, (byte) 0x8e, (byte) 0x72, (byte) 0x6c, (byte) 0x1e, (byte) 0xc0, (byte) 0x2b,
        (byte) 0x7e, (byte) 0xbf, (byte) 0xe9, (byte) 0x2b, (byte) 0x23, (byte) 0xd9, (byte) 0xec, (byte) 0x34
    }};

    private byte[] nonce1 = new byte[] {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    private byte[] nonce2 = new byte[] {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private byte[] key = vector[0], plaintext = vector[1], ciphertext = vector[2];

    private CBCCipher encrypt, decrypt;
    private byte[] out;

    @Before
    public void setUp() throws Exception {
        encrypt = new CBCCipher(key, true, nonce1);
        decrypt = new CBCCipher(key, false, nonce1);
    }

    @After
    public void tearDown() throws Exception {
        encrypt = decrypt = null;
        out = null;
    }

    @Test
    public void testEncryptCorrectCiphertext() {
        out = encrypt.process(plaintext);
        assertThat(out, is(equalTo(ciphertext)));
    }

    @Test
    public void testEncryptDifferentCiphertextForIdenticalBlocks() {
        encrypt.process(plaintext);
        out = encrypt.process(plaintext);
        assertThat(out, is(not(equalTo(ciphertext))));
    }

    @Test
    public void testEncryptCiphertextDependsOnIV() {
        encrypt = new CBCCipher(key, true, nonce2);
        out = encrypt.process(plaintext);
        assertThat(out, is(not(equalTo(ciphertext))));
    }

    @Test
    public void testDecryptCorrectPlaintext() {
        out = decrypt.process(ciphertext);
        assertThat(out, is(equalTo(plaintext)));
    }

    @Test
    public void testDecryptDependsOnIV() {
        decrypt = new CBCCipher(key, false, nonce2);
        out = decrypt.process(ciphertext);
        assertThat(out, is(not(equalTo(plaintext))));
    }

}
