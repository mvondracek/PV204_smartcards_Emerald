/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */
package e2e;

import static applet.EmeraldProtocol.CLA_ENCRYPTED;
import static applet.EmeraldProtocol.CLA_PLAINTEXT;
import static applet.EmeraldProtocol.MESSAGE_GET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_LENGTH;
import static applet.EmeraldProtocol.MESSAGE_OK_GET;
import static applet.EmeraldProtocol.MESSAGE_OK_SET;
import static applet.EmeraldProtocol.MESSAGE_SET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_TYPE_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_LENGTH_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOTS_COUNT;
import static applet.EmeraldProtocol.PASSWORD_SLOT_ID_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_VALUE_OFFSET;
import static applet.EmeraldProtocol.aesKeyDevelopmentTODO;
import applet.SecureChannelManager;
import cardTools.CardManager;
import static cardTools.Util.prepareParameterData;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import tests.BaseTest;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;


/**
 * End-to-End tests for {@link applet.EmeraldApplet} based on APDU communication with applet
 * instance (by default in simulator).
 */
public class EmeraldAppletAPDUTest extends BaseTest {
    private static final byte[] TEST_PIN = new byte[]{1, 2, 3, 4};
    private static final byte[] PARAMETER_DATA = prepareParameterData(
        APPLET_AID_BYTE, new byte[0], TEST_PIN);

    @Test
    public void plaintextMessage() throws Exception {
        final CommandAPDU command = new CommandAPDU(CLA_PLAINTEXT, 0x00, 0x00, 0x00);
        final ResponseAPDU response = connect(PARAMETER_DATA).transmit(command);
        Assert.assertNotNull(response);
        Assert.assertEquals(0x9000, response.getSW());
        Assert.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, response.getData());
    }

    @Test
    public void setSinglePassword() throws Exception {
        byte[] password = "mySuperSecretPassword".getBytes();
        for (byte passwordSlotId = 0; passwordSlotId < PASSWORD_SLOTS_COUNT; passwordSlotId++) {
            final SecureChannelManager secureChannelManager = new SecureChannelManager();
            // TODO we use static AES key until J-PAKE is implemented
            secureChannelManager.setKey(aesKeyDevelopmentTODO); // TODO replace with J-PAKE

            byte[] plaintext = new byte[MESSAGE_LENGTH];
            plaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_SET_PASSWORD;
            plaintext[PASSWORD_SLOT_ID_OFFSET] = passwordSlotId;
            plaintext[PASSWORD_LENGTH_OFFSET] = (byte) password.length;
            System.arraycopy(password, 0, plaintext, PASSWORD_VALUE_OFFSET, password.length);

            byte[] ciphertext = secureChannelManager.encrypt(plaintext);
            CommandAPDU command = new CommandAPDU(CLA_ENCRYPTED, 0x00, 0x00, 0x00, ciphertext);

            final ResponseAPDU response = connect(PARAMETER_DATA).transmit(command);

            Assert.assertNotNull(response);
            Assert.assertEquals(0x9000, response.getSW());

            byte[] responsePlaintext = secureChannelManager.decrypt(response.getData());
            Assert.assertEquals(responsePlaintext.length, MESSAGE_LENGTH);
            Assert.assertEquals(responsePlaintext[MESSAGE_TYPE_OFFSET], MESSAGE_OK_SET);
        }
    }

    @Test
    public void setGetSinglePassword() throws Exception {
        byte[] password = "mySuperSecretPassword".getBytes();
        for (byte passwordSlotId = 0; passwordSlotId < PASSWORD_SLOTS_COUNT; passwordSlotId++) {
            //region set password
            final SecureChannelManager secureChannelManager = new SecureChannelManager();
            // TODO we use static AES key until J-PAKE is implemented
            secureChannelManager.setKey(aesKeyDevelopmentTODO); // TODO replace with J-PAKE

            byte[] plaintext = new byte[MESSAGE_LENGTH];
            plaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_SET_PASSWORD;
            plaintext[PASSWORD_SLOT_ID_OFFSET] = passwordSlotId;
            plaintext[PASSWORD_LENGTH_OFFSET] = (byte) password.length;
            System.arraycopy(password, 0, plaintext, PASSWORD_VALUE_OFFSET, password.length);

            byte[] ciphertext = secureChannelManager.encrypt(plaintext);
            CommandAPDU command = new CommandAPDU(CLA_ENCRYPTED, 0x00, 0x00, 0x00, ciphertext);

            final CardManager cardManager = connect(PARAMETER_DATA);
            ResponseAPDU response = cardManager.transmit(command);

            Assert.assertNotNull(response);
            Assert.assertEquals(0x9000, response.getSW());

            byte[] responsePlaintext = secureChannelManager.decrypt(response.getData());
            Assert.assertEquals(responsePlaintext.length, MESSAGE_LENGTH);
            Assert.assertEquals(responsePlaintext[MESSAGE_TYPE_OFFSET], MESSAGE_OK_SET);
            //endregion

            //region get password
            plaintext = new byte[MESSAGE_LENGTH];
            plaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_GET_PASSWORD;
            plaintext[PASSWORD_SLOT_ID_OFFSET] = passwordSlotId;

            ciphertext = secureChannelManager.encrypt(plaintext);
            command = new CommandAPDU(CLA_ENCRYPTED, 0x00, 0x00, 0x00, ciphertext);
            response = cardManager.transmit(command);

            Assert.assertNotNull(response);
            Assert.assertEquals(0x9000, response.getSW());

            responsePlaintext = secureChannelManager.decrypt(response.getData());
            Assert.assertEquals(responsePlaintext.length, MESSAGE_LENGTH);
            Assert.assertEquals(responsePlaintext[MESSAGE_TYPE_OFFSET], MESSAGE_OK_GET);
            Assert.assertEquals(responsePlaintext[PASSWORD_SLOT_ID_OFFSET], passwordSlotId);
            Assert.assertEquals(responsePlaintext[PASSWORD_LENGTH_OFFSET], (byte) password.length);
            byte[] retrievedPassword = Arrays.copyOfRange(responsePlaintext, PASSWORD_VALUE_OFFSET,
                PASSWORD_VALUE_OFFSET + responsePlaintext[PASSWORD_LENGTH_OFFSET]);
            Assert.assertArrayEquals(password, retrievedPassword);
            //endregion
        }
    }
}
