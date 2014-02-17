package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementation of AES Encryption algorithm.
 *
 * @author Nikita Frolov
 */
public class ForwardCipher extends AbstractCipher {

    /**
     * @param   key     cipher key
     */
    public ForwardCipher(final byte[] key) {
        super(key);
    }

    /**
     * Performs encryption transformation on the block.
     *
     * @param   in      plaintext block as an array of 16 bytes
     * @return          ciphertext
     */
    @Override
    public byte[] processBlock(final byte[] in) {
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
     * SubBytes() function as described in the standard.
     *
     * @param   state   state to process
     */
    private void subBytes(final byte[] state) {
        subBytes(state, SBox.FORWARD);
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

}
