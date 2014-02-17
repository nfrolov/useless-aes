package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementation of the CBC mode of operation.
 *
 * @author Nikita Frolov
 */
public class CBCCipher implements BlockCipher {

    private final boolean encryption;
    private final BlockCipher cipher;

    private byte[] previous;

    /**
     * @param   key     cipher key
     * @param   encryption  true for encryption cipher
     * @param   nonce   initialization vector
     */
    public CBCCipher(final byte[] key, final boolean encryption, final byte[] nonce) {
        this.encryption = encryption;
        this.cipher = encryption ? new ForwardCipher(key) : new InverseCipher(key);
        this.previous = Arrays.copyOf(nonce, getBlockSize());
    }

    /**
     * Returns cipher's block size in bytes.
     *
     * @return          size in bytes
     */
    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    /**
     * Performs encryption/decryption on the block.
     *
     * @param   in      input block
     * @return          processed block
     */
    @Override
    public byte[] process(byte[] in) {
        if (getBlockSize() != in.length) {
            throw new IllegalArgumentException("Block length is not " + getBlockSize() + " bytes.");
        }

        byte[] out;

        if (encryption) {
            out = new byte[in.length];
            for (int i = 0; i < in.length; ++i) {
                out[i] = (byte) (in[i] ^ previous[i]);
            }
            out = cipher.process(out);
            System.arraycopy(out, 0, previous, 0, previous.length);
        } else {
            out = cipher.process(in);
            for (int i = 0; i < in.length; ++i) {
                out[i] ^= previous[i];
            }
            System.arraycopy(in, 0, previous, 0, previous.length);
        }

        return out;
    }

}
