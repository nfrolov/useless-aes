package tiralabra.aes.core;

/**
 * Implementation of the ECB mode of operation.
 *
 * @author Nikita Frolov
 */
public class ECBCipher implements BlockCipher {

    private final BlockCipher cipher;

    public ECBCipher(final byte[] key, final boolean encryption) {
        this.cipher = encryption ? new ForwardCipher(key) : new InverseCipher(key);
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
        return cipher.process(in);
    }

}
