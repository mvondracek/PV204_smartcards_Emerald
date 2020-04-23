/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import java.util.Arrays;

public class SecureChannelManagerBase {
    private static final byte ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE = (byte) 16;
    private static final byte ALG_SHA_256_SIZE = (byte) 32;
    private static final byte ALG_AES_CBC_ISO9797_M2_IV_SIZE = (byte) 16;
    private final AESKey aesKey;
    private final Cipher aesEncrypt;
    private final Cipher aesDecrypt;
    private final HMACKey hmacKey;
    private final Signature hmacSign;
    private final Signature hmacVerify;
    private final MessageDigest hashChainGenerator;
    private final byte[] hashChainEncryption;
    private final byte[] hashChainDecryption;
    private final MessageDigest kdf;
    private final byte[] kdfBuffer;
    private final RandomData ivGenerator;
    private boolean secureChannelEstablished = false;

    public SecureChannelManagerBase() {
        // NOTE: We cannot use AES-GCM as JCardSim does not support AEADCipher.ALG_AES_GCM. It
        //       throws CryptoException with reason code CryptoException.NO_SUCH_ALGORITHM.
        //       https://github.com/licel/jcardsim/issues/153

        // init AES cipher
        aesEncrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        aesDecrypt = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        hmacSign = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        hmacVerify = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256,
            false);
        hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
            KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);

        hashChainGenerator = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hashChainEncryption = new byte[ALG_SHA_256_SIZE];
        hashChainDecryption = new byte[ALG_SHA_256_SIZE];

        kdf = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        kdfBuffer = new byte[kdf.getLength()];

        ivGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    public void clearSessionData() {
        secureChannelEstablished = false;
        aesKey.clearKey();
        hmacKey.clearKey();
        Util.arrayFillNonAtomic(hashChainEncryption, (short) 0, (short) hashChainEncryption.length,
            (byte) 0);
        Util.arrayFillNonAtomic(hashChainDecryption, (short) 0, (short) hashChainEncryption.length,
            (byte) 0);
        Util.arrayFillNonAtomic(kdfBuffer, (short) 0, (short) kdfBuffer.length, (byte) 0);
    }

    public boolean isSecureChannelEstablished() {
        return secureChannelEstablished;
    }

    void setKey(byte[] sessionKey) {
        if ((short) (sessionKey.length * 8) != KeyBuilder.LENGTH_AES_256) {
            // incorrect sessionKey length
            throw new EmIllegalArgumentException();
        }
        if (isSecureChannelEstablished()) {
            // sessionKey was already set during this session
            throw new EmIllegalStateException();
        }
        secureChannelEstablished = true;

        // configure AES
        aesKey.setKey(sessionKey, (short) 0);
        aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT);

        // configure HMAC
        kdf.doFinal(sessionKey, (short) 0, (short) sessionKey.length, kdfBuffer, (short) 0);
        hmacKey.setKey(kdfBuffer, (short) 0, kdf.getLength());
        hmacSign.init(hmacKey, Signature.MODE_SIGN);
        hmacVerify.init(hmacKey, Signature.MODE_VERIFY);

        // generate first value of hash chain
        kdf.doFinal(sessionKey, (short) 0, (short) sessionKey.length, kdfBuffer, (short) 0);
        Util.arrayCopyNonAtomic(kdfBuffer, (short) 0, hashChainEncryption, (short) 0,
            (short) hashChainEncryption.length);
        Util.arrayCopyNonAtomic(kdfBuffer, (short) 0, hashChainDecryption, (short) 0,
            (short) hashChainDecryption.length);
    }

    /**
     * Set 16-byte IV for AES.
     *
     * @param ivBuffer buffer wit IV
     * @param ivOffset offset of IV in buffer
     */
    public void setIv(byte[] ivBuffer, short ivOffset) {
        aesEncrypt.init(aesKey, Cipher.MODE_ENCRYPT, ivBuffer, ivOffset,
            ALG_AES_CBC_ISO9797_M2_IV_SIZE);
        aesDecrypt.init(aesKey, Cipher.MODE_DECRYPT, ivBuffer, ivOffset,
            ALG_AES_CBC_ISO9797_M2_IV_SIZE);
    }

    public byte[] encrypt(byte[] plaintext) {
        if (!aesKey.isInitialized() || !hmacKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }

        byte[] ivBuffer = new byte[ALG_AES_CBC_ISO9797_M2_IV_SIZE];
        ivGenerator.generateData(ivBuffer, (short) 0, ALG_AES_CBC_ISO9797_M2_IV_SIZE);
        setIv(ivBuffer, (short) 0);

        byte[] hashChainAndPlaintext = new byte[hashChainGenerator.getLength() + plaintext.length];
        // copy current hash chain
        Util.arrayCopyNonAtomic(hashChainEncryption, (short) 0, hashChainAndPlaintext,
            (short) 0, (short) hashChainEncryption.length);
        // copy plaintext
        Util.arrayCopyNonAtomic(plaintext, (short) 0, hashChainAndPlaintext,
            hashChainGenerator.getLength(), (short) plaintext.length);
        // generate next hash chain
        hashChainGenerator.doFinal(hashChainEncryption, (short) 0,
            (short) hashChainEncryption.length, hashChainEncryption, (short) 0);

        byte[] ciphertextBuffer = new byte[hashChainAndPlaintext.length
            + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE * 2];
        final short ciphertextLength = aesEncrypt.doFinal(hashChainAndPlaintext, (short) 0,
            (short) hashChainAndPlaintext.length, ciphertextBuffer, (short) 0);
        byte[] ciphertext = Arrays.copyOf(ciphertextBuffer, ciphertextLength);

        byte[] hmacBuffer = new byte[256];
        final short hmacLength = hmacSign.sign(ciphertext, (short) 0, (short) ciphertext.length,
            hmacBuffer, (short) 0);
        byte[] hmac = Arrays.copyOf(hmacBuffer, hmacLength);

        byte[] ivAndHmacAndCiphertext = new byte[ivBuffer.length + hmac.length + ciphertext.length];
        short currentOffset = 0;
        System.arraycopy(ivBuffer, 0, ivAndHmacAndCiphertext, currentOffset, ivBuffer.length);
        currentOffset += ivBuffer.length;
        System.arraycopy(hmac, 0, ivAndHmacAndCiphertext, currentOffset, hmac.length);
        currentOffset += hmac.length;
        System.arraycopy(ciphertext, 0, ivAndHmacAndCiphertext, currentOffset,
            ciphertext.length);
        return ivAndHmacAndCiphertext;
    }

    public byte[] decrypt(byte[] ivAndHmacAndCiphertext, short offset, short length)
        throws EmeraldProtocolException {
        if (!aesKey.isInitialized() || !hmacKey.isInitialized() || !isSecureChannelEstablished()) {
            // key is not set
            throw new EmIllegalStateException();
        }
        short currentOffset = offset;
        byte[] iv = Arrays.copyOfRange(ivAndHmacAndCiphertext, currentOffset,
            currentOffset + ALG_AES_CBC_ISO9797_M2_IV_SIZE);
        currentOffset += ALG_AES_CBC_ISO9797_M2_IV_SIZE;
        byte[] hmac = Arrays.copyOfRange(ivAndHmacAndCiphertext, currentOffset,
            currentOffset + 32);
        currentOffset += 32;
        byte[] ciphertext = Arrays.copyOfRange(ivAndHmacAndCiphertext, currentOffset,
            offset + length);

        final boolean verified = hmacVerify.verify(ciphertext, (short) 0, (short) ciphertext.length,
            hmac, (short) 0, (short) hmac.length);
        if (!verified) {
            // invalid HMAC
            throw new EmeraldProtocolException();
        }
        setIv(iv, (short) 0);

        byte[] plaintextBuffer = new byte[ciphertext.length
            + ALG_AES_CBC_ISO9797_M2_BLOCK_SIZE * 2];
        final short plaintextLength = aesDecrypt.doFinal(ciphertext, (short) 0,
            (short) ciphertext.length, plaintextBuffer, (short) 0);
        byte[] hashChainAndPlaintext = Arrays.copyOf(plaintextBuffer, plaintextLength);

        // compare current value of hash chain with the one in decrypted plaintext
        if (0 != Util.arrayCompare(hashChainAndPlaintext, (short) 0, hashChainDecryption, (short) 0,
            (short) hashChainDecryption.length)) {
            // invalid hash chain
            throw new EmeraldProtocolException();
        }
        // generate next hash chain
        hashChainGenerator.doFinal(hashChainDecryption, (short) 0,
            (short) hashChainDecryption.length, hashChainDecryption, (short) 0);

        return Arrays.copyOfRange(hashChainAndPlaintext,
            (short) hashChainDecryption.length, hashChainAndPlaintext.length);
    }
}
