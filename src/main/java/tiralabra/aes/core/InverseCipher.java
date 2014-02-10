package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementation of AES Decryption algorithm.
 *
 * @author Nikita Frolov
 */
public class InverseCipher extends AbstractCipher {

    public InverseCipher(final byte[] key) {
        super(key);
    }

    /**
     * Performcs decryption transformation on the block.
     *
     * @param   in      ciphertext block as an array of 16 bytes
     * @return          plaintext
     */
    public byte[] decrypt(final byte[] in) {
        if (16 != in.length) {
            throw new IllegalArgumentException("Block length is not 128 bits.");
        }

        final byte[] state = Arrays.copyOf(in, in.length);

        addRoundKey(state, 10);

        for (int round = 9; round > 0; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        return state;
    }

    /**
     * InvShiftRows() function described in the standard.
     *
     * @param   state   state to process
     */
    private void invShiftRows(final byte[] state) {
        byte temp;

        temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;

        temp = state[14];
        state[14] = state[6];
        state[6] = temp;
        temp = state[10];
        state[10] = state[2];
        state[2] = temp;

        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }

    /**
     * InvSubBytes() function described in the standard.
     *
     * @param   state   state to process
     */
    private void invSubBytes(final byte[] state) {
        subBytes(state, SBox.INVERSE);
    }

    /**
     * InvMixColumns() function described in the standard.
     *
     * @param   state   state to process
     */
    private void invMixColumns(final byte[] state) {
        final byte[] product = new byte[state.length];

        for (int c = 0; c < 4; ++c) {
            product[4 * c + 0] = (byte) (gmul(state[4 * c + 0], 0x0e) ^ gmul(state[4 * c + 1], 0x0b) ^ gmul(state[4 * c + 2], 0x0d) ^ gmul(state[4 * c + 3], 0x09));
            product[4 * c + 1] = (byte) (gmul(state[4 * c + 0], 0x09) ^ gmul(state[4 * c + 1], 0x0e) ^ gmul(state[4 * c + 2], 0x0b) ^ gmul(state[4 * c + 3], 0x0d));
            product[4 * c + 2] = (byte) (gmul(state[4 * c + 0], 0x0d) ^ gmul(state[4 * c + 1], 0x09) ^ gmul(state[4 * c + 2], 0x0e) ^ gmul(state[4 * c + 3], 0x0b));
            product[4 * c + 3] = (byte) (gmul(state[4 * c + 0], 0x0b) ^ gmul(state[4 * c + 1], 0x0d) ^ gmul(state[4 * c + 2], 0x09) ^ gmul(state[4 * c + 3], 0x0e));
        }

        System.arraycopy(product, 0, state, 0, product.length);
    }

}
