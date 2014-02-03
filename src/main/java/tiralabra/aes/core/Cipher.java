package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementation of AES Encryption algorithm.
 *
 * @author Nikita Frolov
 */
public class Cipher {

    private static final KeyScheduler keyScheduler = new KeyScheduler();
    private static final byte[] sbox = SBox.FORWARD;

    private final int[] roundKeys;

    /**
     * @param   key     cipher key
     */
    public Cipher(final byte[] key) {
        this.roundKeys = keyScheduler.schedule(key);
    }

    /**
     * Performs encryption transformation on the block.
     *
     * @param   in      plaintext block as an array of 16 bytes
     * @return          ciphertext
     */
    public byte[] encrypt(final byte[] in) {
        if (16 != in.length) {
            throw new IllegalArgumentException("Block length is not 128 bits.");
        }

        final byte[] state = Arrays.copyOf(in, in.length);

        addRoundKey(state, 0);

        for (int round = 1; round < 10; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, 10);

        return state;
    }

    /**
     * AddRoundKey() function described in the standard.
     *
     * @param   state   state to process
     * @param   round   round number
     */
    private void addRoundKey(final byte[] state, final int round) {
        final int roundKeyOffset = round * 4;

        for (int c = 0; c < 4; ++c) {
            int column = packWord(state, 4 * c);
            column ^= roundKeys[roundKeyOffset + c];
            unpackWord(column, state, 4 * c);
        }
    }

    /**
     * SubBytes() function as described in the standard.
     *
     * @param   state   state to process
     */
    private void subBytes(final byte[] state) {
        for (int i = 0; i < state.length; ++i) {
            state[i] = sbox[state[i] & 0xff];
        }
    }

    /**
     * ShiftRows() function described in the standard.
     *
     * @param state
     */
    private void shiftRows(final byte[] state) {
        byte temp;

        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        temp = state[14];
        state[14] = state[6];
        state[6] = temp;
        temp = state[10];
        state[10] = state[2];
        state[2] = temp;

        temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    /**
     * MixColumns() function described in the standard.
     *
     * @param   state   state to process
     */
    private void mixColumns(final byte[] state) {
        final byte[] product = new byte[state.length];

        for (int c = 0; c < 4; ++c) {
            product[4 * c + 0] = (byte) (gmul(state[4 * c + 0], 2) ^ gmul(state[4 * c + 1], 3) ^ state[4 * c + 3] ^ state[4 * c + 2]);
            product[4 * c + 1] = (byte) (state[4 * c + 0] ^ gmul(state[4 * c + 1], 2) ^ gmul(state[4 * c + 2], 3) ^ state[4 * c + 3]);
            product[4 * c + 2] = (byte) (state[4 * c + 0] ^ state[4 * c + 1] ^ gmul(state[4 * c + 2], 2) ^ gmul(state[4 * c + 3], 3));
            product[4 * c + 3] = (byte) (gmul(state[4 * c + 0], 3) ^ state[4 * c + 1] ^ state[4 * c + 2] ^ gmul(state[4 * c + 3], 2));
        }

        System.arraycopy(product, 0, state, 0, product.length);
    }

    private static int gmul(final byte a, final int b) {
        return gmul(a & 0xff, b);
    }

    /**
     * Performs multiplication in Rijndael Galois field.
     * Source of inspiration: http://www.samiam.org/galois.html
     *
     * @param   a       first factor
     * @param   b       second factor
     * @return          product
     */
    private static int gmul(int a, int b) {
        int product = 0;

        for (int i = 0; i < 8; ++i) {
            if ((b & 1) == 1) {
                product ^= a;
            }
            final int hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set == 0x80) {
                a ^= 0x1b;
            }
            b >>= 1;
        }

        return product;
    }

    private static int packWord(final byte[] bs, final int offset) {
        return (bs[offset] & 0xff) | ((bs[offset + 1] & 0xff) << 8) | ((bs[offset + 2] & 0xff) << 16) | (bs[offset + 3] << 24);
    }

    private static void unpackWord(final int word, final byte[] bs, final int offset) {
        bs[offset] = (byte) (word & 0xff);
        bs[offset + 1] = (byte) ((word >> 8) & 0xff);
        bs[offset + 2] = (byte) ((word >> 16) & 0xff);
        bs[offset + 3] = (byte) ((word >> 24) & 0xff);
    }

}
