/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import static applet.EmeraldProtocol.MESSAGE_OK_GET;
import static applet.EmeraldProtocol.MESSAGE_OK_SET;
import static applet.EmeraldProtocol.MESSAGE_TYPE_OFFSET;
import static applet.EmeraldProtocol.CLA_ENCRYPTED;
import static applet.EmeraldProtocol.CLA_PLAINTEXT;
import static applet.EmeraldProtocol.MESSAGE_GET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_SET_PASSWORD;
import static applet.EmeraldProtocol.PASSWORD_LENGTH_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOT_ID_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOT_LENGTH;
import static applet.EmeraldProtocol.PASSWORD_VALUE_OFFSET;
import static applet.EmeraldProtocol.aesKeyDevelopmentTODO;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;

public class EmeraldApplet extends Applet implements MultiSelectable {
    public static final byte PIN_LENGTH = 4;

    /**
     * Persistent PIN storage in EEPROM.
     * TODO `javacard.framework.OwnerPIN` is not suitable as we need to read PIN value for J-PAKE
     */
    private final byte[] pin; // TODO store pin securely
    private final SecureChannelManager secureChannelManager;

    private final byte[] ramBuffer;

    //region applet example functionality: password manager
    private final byte[] userPasswordSlot1;
    private final byte[] userPasswordSlot1UsedLength;
    private final byte[] userPasswordSlot2;
    private final byte[] userPasswordSlot2UsedLength;
    private final byte[] userPasswordSlot3;
    private final byte[] userPasswordSlot3UsedLength;
    //endregion



    /**
     * Create instance of the applet.
     *
     * <p>Should be used from {@link #install} method. See {@link #install} for description of
     * parameters. Calls {@link #register()} on successful initialization.
     */
    EmeraldApplet(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        byte instanceAidLength = bArray[bOffset];
        byte controlInfoLength = bArray[(short) (bOffset + 1 + instanceAidLength)];
        byte appletDataLength = bArray[(short) (bOffset + 1 + instanceAidLength + 1 + controlInfoLength)];

        short appletDataOffset = (short) (bOffset + 1 + instanceAidLength + 1 + controlInfoLength + 1);
        // first byte of applet data:
        // bArray[bOffset + 1 + instanceAidLength + 1 + controlInfoLength + 1]
        // last byte of applet data:
        // bArray[bOffset + 1 + instanceAidLength + 1 + controlInfoLength + 1 + appletDataLength - 1]

        // check if we have received PIN
        if (appletDataLength != PIN_LENGTH) {
            // unexpected length of applet data
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        // check if bytes of received PIN are only digits <0;9>
        for (short i = 0; i < PIN_LENGTH; i++) {
            byte pinDigit = bArray[(short) (appletDataOffset + i)];
            if (!(0 <= pinDigit && pinDigit <= 9)) {
                // byte value of PIN digit not in range <0;9>
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        }

        // create persistent pin in EEPROM
        pin = new byte[PIN_LENGTH];
        Util.arrayCopy(bArray, appletDataOffset, pin, (short) 0, PIN_LENGTH);

        // init SecureChannelManager
        secureChannelManager = new SecureChannelManager();
        // TODO we use static AES key until J-PAKE is implemented
        secureChannelManager.setKey(aesKeyDevelopmentTODO); // TODO replace with J-PAKE

        ramBuffer = JCSystem.makeTransientByteArray((short) 160, JCSystem.CLEAR_ON_DESELECT);
        //region applet example functionality: password manager
        // persistent storage for the password manager
        userPasswordSlot1 = new byte[PASSWORD_SLOT_LENGTH];
        userPasswordSlot1UsedLength = new byte[]{0};
        userPasswordSlot2 = new byte[PASSWORD_SLOT_LENGTH];
        userPasswordSlot2UsedLength = new byte[]{0};
        userPasswordSlot3 = new byte[PASSWORD_SLOT_LENGTH];
        userPasswordSlot3UsedLength = new byte[]{0};
        //endregion

        // initialization successful
        register();
    }

    /**
     * Create an instance of the applet by the Java Card runtime environment.
     *
     * <p>Installation parameters are provided in bArray as follows:
     * <ul>
     *      <li>bArray[bOffset] = length(Li) of instance AID,
     *      bArray[bOffset+1..bOffset+Li] = instance AID bytes,</li>
     *      <li>bArray[bOffset+Li+1]= length(Lc) of control info,
     *      bArray[bOffset+Li+2..bOffset+Li+Lc+1] = control info,</li>
     *      <li>bArray[bOffset+Li+Lc+2] = length(La) of applet data,
     *      bArray[bOffset+Li+Lc+3..bOffset+Li+Lc+La+2] = applet data</li>
     * </ul>
     * In the above format, any of the lengths: Li, Lc or La may be zero. The control information is
     * implementation dependent. The bArray object is a global array. If the applet desires to
     * preserve any of this data, it should copy the data into its own object. bArray is zeroed by
     * the Java Card runtime environment after the return from the install() method.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray The maximum value of
     *                bLength is 127.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new EmeraldApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        // ignore SELECT command
        // if selectingApplet()
        if ((apduBuffer[ISO7816.OFFSET_CLA] == 0) &&
            (apduBuffer[ISO7816.OFFSET_INS] == (byte) (0xA4))) {
            return;
        }

        if(apduBuffer[ISO7816.OFFSET_CLA] == CLA_PLAINTEXT) {
            byte[] reply = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
            Util.arrayCopyNonAtomic(
                reply, (short) 0,
                apdu.getBuffer(), (short) 0,
                (short) reply.length);
            apdu.setOutgoingAndSend((short) 0, (short) reply.length);
            return;
        }

        if(apduBuffer[ISO7816.OFFSET_CLA] == CLA_ENCRYPTED){
            short dataLength = apdu.setIncomingAndReceive();
            // save ciphertext to ramBuffer
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, ramBuffer, (short) 0, dataLength);
            byte[] plaintext = secureChannelManager.decrypt(ramBuffer);

            //region applet example functionality: password manager
            byte[] selectedPasswordSlot;
            byte[] selectedPasswordSlotUsedLength;

            switch(plaintext[PASSWORD_SLOT_ID_OFFSET]){
                case 1:
                    selectedPasswordSlot = userPasswordSlot1;
                    selectedPasswordSlotUsedLength = userPasswordSlot1UsedLength;
                    break;
                case 2:
                    selectedPasswordSlot = userPasswordSlot2;
                    selectedPasswordSlotUsedLength = userPasswordSlot2UsedLength;
                    break;
                case 3:
                    selectedPasswordSlot = userPasswordSlot3;
                    selectedPasswordSlotUsedLength = userPasswordSlot3UsedLength;
                    break;
                default:
                    // incorrect password slot
                    // attacker is trying to communicate with incorrect PIN
                    // TODO count incorrect counter and consider blocking the card
                    return;
            }

            switch(plaintext[MESSAGE_TYPE_OFFSET]){
                case MESSAGE_SET_PASSWORD: {
                    if(plaintext[PASSWORD_LENGTH_OFFSET] > PASSWORD_SLOT_LENGTH){
                        // invalid password length
                        // attacker is trying to communicate with incorrect PIN
                        // TODO count incorrect counter and consider blocking the card
                        return;
                    }
                    selectedPasswordSlotUsedLength[0] = plaintext[PASSWORD_LENGTH_OFFSET];
                    // set password to selected slot
                    Util.arrayCopyNonAtomic(plaintext, PASSWORD_VALUE_OFFSET,
                        selectedPasswordSlot, (short) 0, selectedPasswordSlotUsedLength[0]);
                    // send response
                    byte[] responsePlaintext = new byte[32];
                    responsePlaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_OK_SET;
                    byte[] responseCiphertext = secureChannelManager.encrypt(responsePlaintext);
                    Util.arrayCopyNonAtomic(responseCiphertext, (short) 0,
                        apduBuffer, ISO7816.OFFSET_CDATA, (short) responseCiphertext.length);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) responseCiphertext.length);
                    break;
                }
                case MESSAGE_GET_PASSWORD: {
                    // send response
                    byte[] responsePlaintext = new byte[32];
                    responsePlaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_OK_GET;
                    responsePlaintext[PASSWORD_SLOT_ID_OFFSET] = plaintext[PASSWORD_SLOT_ID_OFFSET];
                    responsePlaintext[PASSWORD_LENGTH_OFFSET] = selectedPasswordSlotUsedLength[0];

                    // get password from selected slot
                    Util.arrayCopyNonAtomic(selectedPasswordSlot, (short) 0,
                        responsePlaintext, PASSWORD_VALUE_OFFSET, selectedPasswordSlotUsedLength[0]);

                    byte[] responseCiphertext = secureChannelManager.encrypt(responsePlaintext);
                    Util.arrayCopyNonAtomic(responseCiphertext, (short) 0,
                        apduBuffer, ISO7816.OFFSET_CDATA, (short) responseCiphertext.length);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) responseCiphertext.length);
                    break;
                }
                default:
                    // incorrect message
                    // attacker is trying to communicate with incorrect PIN
                    // TODO count incorrect counter and consider blocking the card
                    return;
            }
            //endregion
        }

    }

    @Override
    public boolean select() {
        clearSessionData();
        return true;
    }

    @Override
    public boolean select(boolean appInstAlreadyActive) {
        clearSessionData();
        return true;
    }

    @Override
    public void deselect() {
        clearSessionData();
    }

    @Override
    public void deselect(boolean appInstAlreadyActive) {
        clearSessionData();
    }

    /**
     * Clear session data in RAM.
     *
     * <p>Intended to be used before and after the applet starts communication session with
     * a reader. In case the card is incorrectly removed, `deselect` methods might not be called.
     * Therefore, it is important to clear data even in `select` method.
     *
     * @see #select()
     * @see #select(boolean)
     * @see #deselect()
     * @see #deselect(boolean)
     */
    private void clearSessionData() {
        // TODO overwrite session data in RAM with random data
    }
}
