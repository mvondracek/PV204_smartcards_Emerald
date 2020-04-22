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

public class SecureChannelManager {
    private final AESKey aesKey;
    private final Cipher aesEncrypt;
    private final Cipher aesDecrypt;

    public SecureChannelManager() {
        // init AES cipher
        aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    }

    public void setKey(byte[] key) {
        if ((short) (key.length * 8) != KeyBuilder.LENGTH_AES_256) {
            // incorrect key length
            throw new EmIllegalArgumentException();
        }
        aesKey.setKey(key, (short) 0);
        aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT);
    }

    public byte[] encrypt(byte[] plaintext) {
        if (!aesKey.isInitialized()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        if (plaintext.length % 16 != 0) {
            // plaintext length is not a multiple of AES block size (16 B)
            throw new EmIllegalArgumentException();
        }
        byte[] ciphertext = new byte[plaintext.length];
        aesEncrypt.doFinal(plaintext, (short) 0, (short) plaintext.length, ciphertext, (short) 0);
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (!aesKey.isInitialized()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        if (ciphertext.length % 16 != 0) {
            // ciphertext length is not a multiple of AES block size (16 B)
            throw new EmIllegalArgumentException();
        }
        byte[] plaintext = new byte[ciphertext.length];
        aesDecrypt.doFinal(ciphertext, (short) 0, (short) ciphertext.length, plaintext, (short) 0);
        return plaintext;
    }
}
