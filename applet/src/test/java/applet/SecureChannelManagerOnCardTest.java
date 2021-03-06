/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import java.util.Arrays;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

class SecureChannelManagerOnCardTest {
    private static final byte[] TEST_PIN = new byte[]{1, 2, 3, 4};

    @Test
    void testEncryptDecrypt() throws EmeraldProtocolException {
        SecureChannelManagerOnCard manager = new SecureChannelManagerOnCard(TEST_PIN);
        byte[] testKey = new byte[]{
            (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE, (byte) 0x22,
            (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF,
            (byte) 0xEE, (byte) 0x22, (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00};
        manager.setKey(testKey);
        byte[] plaintext = new byte[]{
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xC0, (byte) 0xDE};
        byte[] ciphertext = manager.encrypt(plaintext);
        Assert.assertFalse(Arrays.equals(plaintext, ciphertext));
        byte[] decrypted = manager.decrypt(ciphertext, (short)0, (short) ciphertext.length);
        Assert.assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptDecryptRepeated() throws EmeraldProtocolException {
        SecureChannelManagerOnCard manager = new SecureChannelManagerOnCard(TEST_PIN);
        byte[] testKey = new byte[]{
            (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE, (byte) 0x22,
            (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF,
            (byte) 0xEE, (byte) 0x22, (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00};
        manager.setKey(testKey);
        byte[] plaintext = new byte[]{
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xC0, (byte) 0xDE};
        for (int i = 0; i < 300; i++) {
            // 300 > range of sessionMessageCounterEncrypted in SecureChannelManagerBase
            byte[] ciphertext = manager.encrypt(plaintext);
            Assert.assertFalse(Arrays.equals(plaintext, ciphertext));
            byte[] decrypted = manager.decrypt(ciphertext, (short)0, (short) ciphertext.length);
            Assert.assertArrayEquals(plaintext, decrypted);
        }
    }
}
