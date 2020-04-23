/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

    import javacard.security.AESKey;
    import javacard.security.HMACKey;
    import javacard.security.KeyBuilder;
    import javacard.security.MessageDigest;
    import javacard.security.Signature;
    import javacardx.crypto.Cipher;

    import java.util.Arrays;

public class SecureChannelManagerBase {
    private final AESKey aesKey;
    private final Cipher aesEncrypt;
    private final Cipher aesDecrypt;
    private final HMACKey hmacKey;
    private final Signature hmacSign;
    private final Signature hmacVerify;

    private byte sessionMessageCounterEncrypted = 0;
    private byte sessionMessageCounterDecrypted = 0;

    private boolean secureChannelEstablished = false;

    private static final byte ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE = (byte) 16;

    public SecureChannelManagerBase() {
        // NOTE: We cannot use AES-GCM as JCardSim does not support AEADCipher.ALG_AES_GCM. It
        //       throws CryptoException with reason code CryptoException.NO_SUCH_ALGORITHM.
        //       https://github.com/licel/jcardsim/issues/153

        // init AES cipher
        aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        hmacSign = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        hmacVerify = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
    }

    public void clearSessionData(){
        secureChannelEstablished = false;
        aesKey.clearKey();
        sessionMessageCounterEncrypted = 0;
        sessionMessageCounterDecrypted = 0;
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

        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        byte[] outputBytes = new byte[hash.getLength()];
        final short hashLength = hash.doFinal(key, (short) 0, (short) key.length, outputBytes, (short) 0);
        hmacKey.setKey(outputBytes, (short) 0, hashLength);
        hmacSign.init(hmacKey, Signature.MODE_SIGN);
        hmacVerify.init(hmacKey, Signature.MODE_VERIFY);

        sessionMessageCounterEncrypted = 0;
        sessionMessageCounterDecrypted = 0;
    }

    public byte[] encrypt(byte[] plaintext) {
        if (!aesKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }

        byte[] counterAndPlaintext = Arrays.copyOf(plaintext, 1 + plaintext.length);
        counterAndPlaintext[counterAndPlaintext.length-1] = sessionMessageCounterEncrypted;
        sessionMessageCounterEncrypted++;

        byte[] ciphertextBuffer = new byte[counterAndPlaintext.length + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE * 2];
        final short ciphertextLength = aesEncrypt.doFinal(counterAndPlaintext, (short) 0, (short) counterAndPlaintext.length, ciphertextBuffer, (short) 0);
        byte[] ciphertext = Arrays.copyOf(ciphertextBuffer, ciphertextLength);

        byte[] signBuff = new byte[256];
        final short signLength = hmacSign.sign(ciphertext, (short) 0, (short) ciphertext.length, signBuff, (short) 0);
        byte[] sign = Arrays.copyOf(signBuff, signLength);

        byte[] hmacAndCiphertext = new byte[sign.length + ciphertext.length];
        System.arraycopy(sign, 0, hmacAndCiphertext, 0, sign.length);
        System.arraycopy(ciphertext, 0, hmacAndCiphertext, sign.length, ciphertext.length);
        return hmacAndCiphertext;
    }

    public byte[] decrypt(byte[] hmacAndCiphertext, short offset, short length) throws EmeraldProtocolException {
        if (!aesKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        byte[] hmac = Arrays.copyOfRange(hmacAndCiphertext, offset, offset + 32);
        byte[] ciphertext = Arrays.copyOfRange(hmacAndCiphertext, offset + 32, offset + length);

        final boolean verified = hmacVerify.verify(ciphertext, (short) 0, (short) ciphertext.length, hmac, (short) 0, (short) hmac.length);
        if(!verified){
            // invalid HMAC
            throw new EmeraldProtocolException();
        }

        byte[] plaintextBuffer = new byte[ciphertext.length + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE * 2];
        final short plaintextLength = aesDecrypt.doFinal(ciphertext, (short) 0, (short) ciphertext.length, plaintextBuffer, (short) 0);
        byte[] counterAndPlaintext = Arrays.copyOf(plaintextBuffer, plaintextLength);
        byte counter = counterAndPlaintext[counterAndPlaintext.length-1];

        if(counter != sessionMessageCounterDecrypted){
            // invalid counter
            throw new EmeraldProtocolException();
        }
        sessionMessageCounterDecrypted++;

        byte[] plaintext = Arrays.copyOfRange(counterAndPlaintext, 0, counterAndPlaintext.length-1);
        return plaintext;
    }
}
