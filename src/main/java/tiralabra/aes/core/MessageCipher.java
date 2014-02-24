package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementations of message cipher using CBC mode and PCKS#7 padding.
 *
 * @author Nikita Frolov
 */
public class MessageCipher {

    private final Padding padding = new Padding();

    private final BlockCipher cipher;
    private final boolean encryption;

    private MessageCipher(final BlockCipher cipher, final boolean encryption) {
        this.cipher = cipher;
        this.encryption = encryption;
    }

    /**
     * Constructs encryption cipher.
     *
     * @param   key         cipher key
     * @param   nonce       IV
     * @return              cipher object
     */
    public static MessageCipher getEncryptionCipher(final byte[] key, final byte[] nonce) {
        return new MessageCipher(new CBCCipher(key, true, key), true);
    }

    /**
     * Constructs decryption cipher.
     *
     * @param   key         cipher key
     * @param   nonce       IV
     * @return              cipher object
     */
    public static MessageCipher getDecryptionCipher(final byte[] key, final byte[] nonce) {
        return new MessageCipher(new CBCCipher(key, false, key), false);
    }

    /**
     * Performs cipher transformation on the whole message.
     *
     * @param   message
     * @return              transformed message
     */
    public byte[] process(byte[] message) {
        byte[] block = new byte[cipher.getBlockSize()];
        int offset = 0;

        if (encryption) {
            message = padding.pad(message, block.length);
        } else {
            message = Arrays.copyOf(message, message.length);
        }

        while (offset < message.length) {
            System.arraycopy(message, offset, block, 0, block.length);
            block = cipher.process(block);
            System.arraycopy(block, 0, message, offset, block.length);
            offset += block.length;
        }

        if (!encryption) {
            message = padding.unpad(message, block.length);
        }

        return message;
    }

}
