package tiralabra.aes.core;

public abstract class AbstractCipher implements BlockCipher {

    private static final KeyScheduler keyScheduler = new KeyScheduler();

    private final int[] roundKeys;

    public AbstractCipher(final byte[] key) {
        roundKeys = keyScheduler.schedule(key);
    }

    /**
     * Returns block size in bytes.
     *
     * @return          block size
     */
    @Override
    public int getBlockSize() {
        return 16;
    }

    /**
     * Performs cipher transformation on the block.
     *
     * @param   in      input block
     * @return          transformed block
     */
    @Override
    public byte[] process(byte[] in) {
        if (getBlockSize() != in.length) {
            throw new IllegalArgumentException("Block length is not 128 bits.");
        }
        return processBlock(in);
    }

    protected abstract byte[] processBlock(byte[] in);

    /**
     * Replace each byte of the state with appropriate value from the specified S-box.
     *
     * @param   state   state to process
     * @param   sbox    sbox used to replace
     */
    protected void subBytes(final byte[] state, final byte[] sbox) {
        for (int i = 0; i < state.length; ++i) {
            state[i] = sbox[state[i] & 0xff];
        }
    }

    /**
     * AddRoundKey() function described in the standard.
     *
     * @param   state   state to process
     * @param   round   round number
     */
    protected void addRoundKey(final byte[] state, final int round) {
        final int roundKeyOffset = round * 4;

        for (int c = 0; c < 4; ++c) {
            int column = packWord(state, 4 * c);
            column ^= roundKeys[roundKeyOffset + c];
            unpackWord(column, state, 4 * c);
        }
    }

    protected static int gmul(final byte a, final int b) {
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
    protected static int gmul(int a, int b) {
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