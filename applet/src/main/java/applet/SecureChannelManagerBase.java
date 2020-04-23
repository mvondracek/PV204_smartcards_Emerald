/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

    import javacard.security.AESKey;
    import javacard.security.KeyBuilder;
    import javacardx.crypto.Cipher;

    import java.util.Arrays;

public class SecureChannelManagerBase {
    private final AESKey aesKey;
    private final Cipher aesEncrypt;
    private final Cipher aesDecrypt;

    private boolean secureChannelEstablished = false;

    private static final byte ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE = (byte) 16;

    public SecureChannelManagerBase() {
        // NOTE: We cannot use AES-GCM as JCardSim does not support AEADCipher.ALG_AES_GCM. It
        //       throws CryptoException with reason code CryptoException.NO_SUCH_ALGORITHM.
        //       https://github.com/licel/jcardsim/issues/153

        // init AES cipher
        aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }

    public void clearSessionData(){
        secureChannelEstablished = false;
        aesKey.clearKey();
    }

    public boolean isSecureChannelEstablished(){
        return secureChannelEstablished;
    }

    void setKey(byte[] key) {
        if ((short) (key.length * 8) != KeyBuilder.LENGTH_AES_256) {
            // incorrect key length
            throw new EmIllegalArgumentException();
        }
        if(isSecureChannelEstablished()){
            // key was already set during this session
            throw new EmIllegalStateException();
        }
        secureChannelEstablished = true;

        aesKey.setKey(key, (short) 0);
        aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT);
    }

    public byte[] encrypt(byte[] plaintext) {
        if (!aesKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        byte[] ciphertext = new byte[plaintext.length + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE];
        final short ciphertextLength = aesEncrypt.doFinal(plaintext, (short) 0, (short) plaintext.length, ciphertext, (short) 0);
        return Arrays.copyOf(ciphertext, ciphertextLength);
    }

    public byte[] decrypt(byte[] ciphertext, short offset, short length) {
        if (!aesKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        if (length % ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE != 0) {
            // ciphertext length is not a multiple of AES block size (16 B)
            throw new EmIllegalArgumentException();
        }
        byte[] plaintext = new byte[length + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE];
        final short plaintextLength = aesDecrypt.doFinal(ciphertext, offset, length, plaintext, (short) 0);
        return Arrays.copyOf(plaintext, plaintextLength);
    }
}
