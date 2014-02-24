package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class InverseCipherParameterizedTest {

    @Parameters
    public static Collection<Object[]> data() {
        return ForwardCipherParameterizedTest.data();
    }

    private final byte[] key, plaintext, ciphertext;

    private InverseCipher cipher;

    public InverseCipherParameterizedTest(byte[] key, byte[] plaintext, byte[] ciphertext) {
        this.key = key;
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;
    }

    @Before
    public void setUp() throws Exception {
        cipher = new InverseCipher(key);
    }

    @Test
    public void testProcess() {
        byte[] ciphertextCopy, actual;

        ciphertextCopy = Arrays.copyOf(ciphertext, ciphertext.length);
        actual = cipher.process(ciphertext);

        assertThat("input ciphertext has been modified", ciphertext, is(equalTo(ciphertextCopy)));
        assertThat(actual, is(equalTo(plaintext)));
    }

}
