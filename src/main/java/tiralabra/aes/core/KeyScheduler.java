package tiralabra.aes.core;

/**
 * Implementation of the AES Key Expansion algorithm.
 *
 * @author Nikita Frolov
 */
public class KeyScheduler {

    private final byte[] sbox = SBox.FORWARD;
    private final int[] rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    public KeyScheduler() {
    }

    /**
     * Generates a series of round keys from the cipher key.
     *
     * @param   key     128-bit key as an array of 16 bytes
     * @return          round keys as a linear array of 4-byte words
     */
    public int[] schedule(final byte[] key) {
        if ((key.length / 4) != 4) {
            throw new IllegalArgumentException("Key length is not 128 bits.");
        }

        final int[] w = new int[44];

        for (int i = 0; i < 4; ++i) {
            w[i] = (key[4 * i] & 0xff) | ((key[4 * i + 1] & 0xff) << 8) | ((key[4 * i + 2] & 0xff) << 16) | (key[4 * i + 3] << 24);
        }

        for (int i = 4; i < 44; ++i) {
            int temp = w[i - 1];
            if (0 == i % 4) {
                temp = rotWord(temp);
                temp = subWord(temp);
                temp = temp ^ rcon[(i / 4) - 1];
            }
            w[i] = w[i - 4] ^ temp;
        }

        return w;
    }

    /**
     * RotWord() function described in the standard.
     * Takes a word [a1,a2,a3,a4] and returns the word [a2,a3,a4,a1].
     *
     * @param   word    4-byte word
     * @return          output word
     */
    private int rotWord(final int word) {
        return (word >>> 8) | (word << 24);
    }

    /**
     * SubWord() function described in the standard.
     * Takes a word and applies a S-box to each of the four bytes.
     *
     * @param   word    4-byte word
     * @return          output word
     */
    private int subWord(final int word) {
        return (sbox[word & 0xff] & 0xff) | ((sbox[(word >> 8) & 0xff] & 0xff) << 8)
                | ((sbox[(word >> 16) & 0xff] & 0xff) << 16) | (sbox[(word >> 24) & 0xff] << 24);
    }

}
