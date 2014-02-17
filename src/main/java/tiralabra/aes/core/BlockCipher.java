package tiralabra.aes.core;

public interface BlockCipher {

    public int getBlockSize();

    public byte[] process(byte[] in);

}
