package tiralabra.aes.core;

public class KeyScheduler {

    private final byte[] sbox = SBox.FORWARD;
    private final int[] rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    public KeyScheduler() {
    }

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

    private int rotWord(final int word) {
        return (word >>> 8) | (word << 24);
    }

    private int subWord(final int word) {
        return (sbox[word & 0xff] & 0xff) | ((sbox[(word >> 8) & 0xff] & 0xff) << 8)
                | ((sbox[(word >> 16) & 0xff] & 0xff) << 16) | (sbox[(word >> 24) & 0xff] << 24);
    }

}
