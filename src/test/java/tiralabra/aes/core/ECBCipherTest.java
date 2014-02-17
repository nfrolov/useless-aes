package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class ECBCipherTest {

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

    private ECBCipher encrypt, decrypt;
    private byte[] out;

    @Before
    public void setUp() throws Exception {
        encrypt = new ECBCipher(vector[0], true);
        decrypt = new ECBCipher(vector[0], false);
    }

    @Test
    public void testEncryptCorrectCiphertext() {
        out = encrypt.process(vector[1]);
        assertThat(out, is(equalTo(vector[2])));
    }

    @Test
    public void testEncryptSameCiphertextForIdenticalBlocks() {
        encrypt.process(vector[1]);
        out = encrypt.process(vector[1]);
        assertThat(out, is(equalTo(vector[2])));
    }

    @Test
    public void testDecryptCorrectPlaintext() {
        out = decrypt.process(vector[2]);
        assertThat(out, is(equalTo(vector[1])));
    }

}
