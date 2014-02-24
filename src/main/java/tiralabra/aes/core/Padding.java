package tiralabra.aes.core;

import java.util.Arrays;

/**
 * Implementation of PKCS#7 padding.
 *
 * @author Nikita Frolov
 */
public class Padding {

    /**
     * @param   pt          message to pad
     * @param   blockSize   block size
     * @return              padded message
     */
    public byte[] pad(final byte[] pt, final int blockSize) {
        final byte[] message;
        final int padding;

        padding = blockSize - (pt.length % blockSize);

        message = new byte[pt.length + padding];
        System.arraycopy(pt, 0, message, 0, pt.length);
        for (int i = pt.length; i < message.length; ++i) {
            message[i] = (byte) padding;
        }

        return message;
    }

    /**
     * @param   pt          message to unpad
     * @param   blockSize   block size
     * @return              unpadded message
     */
    public byte[] unpad(final byte[] pt, final int blockSize) {
        final byte[] message;
        final int padding;

        padding = pt[pt.length - 1];
        for (int i = 0; i < padding; ++i) {
            if (padding != pt[pt.length - i - 1]) {
                throw new IllegalArgumentException("Invalid block padding");
            }
        }

        message = Arrays.copyOf(pt, pt.length - padding);

        return message;
    }

}
