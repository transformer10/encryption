package encryption;

public interface SymmetricalEncryption {
    void setKey(byte[] key);

    byte[] encryption(byte[] data);

    byte[] decryption(byte[] data);
}
