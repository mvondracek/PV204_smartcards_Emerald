/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import static applet.EmeraldProtocol.APDU_APPLET_BLOCKED;
import static applet.EmeraldProtocol.CLA_ENCRYPTED;
import static applet.EmeraldProtocol.CLA_KEY_AGREEMENT;
import static applet.EmeraldProtocol.CLA_PLAINTEXT;
import static applet.EmeraldProtocol.PIN_LENGTH;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class EmeraldApplet extends Applet implements ExtendedLength {
    /**
     * Persistent PIN storage in EEPROM.
     * TODO `javacard.framework.OwnerPIN` is not suitable as we need to read PIN value for J-PAKE
     */
    private final byte[] pin; // TODO store pin securely
    private final SecureChannelManagerOnCard secureChannelManagerOnCard;
    private final PasswordManagerSubApplet passwordManagerSubApplet;

    /**
     * Signals whether this applet instance is blocked due to security alert counter depleted.
     * @see #securityAlertCountdown
     */
    private boolean isAppletBlocked = false;
    /**
     * When this field reaches 0, applet is blocked.
     * @see #isAppletBlocked
     */
    private byte securityAlertCountdown = 3;

    /**
     * Create instance of the applet.
     *
     * <p>Should be used from {@link #install} method. See {@link #install} for description of
     * parameters. Calls {@link #register()} on successful initialization.
     */
    EmeraldApplet(byte[] bArray, short bOffset, @SuppressWarnings("unused") byte bLength) throws ISOException {
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

        // init SecureChannelManagerOnCard
        secureChannelManagerOnCard = new SecureChannelManagerOnCard(pin);

        passwordManagerSubApplet = new PasswordManagerSubApplet();

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
        if (selectingApplet()) {
            // apduBuffer[ISO7816.OFFSET_CLA] == 0
            // apduBuffer[ISO7816.OFFSET_INS] == (byte) (0xA4)
            return;
        }

        if(isAppletBlocked){
            respondAppletBlocked(apdu);
        }

        try {
            switch (apduBuffer[ISO7816.OFFSET_CLA]) {
                case CLA_PLAINTEXT: {
                    // example plaintext communication
                    byte[] reply = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
                    Util.arrayCopyNonAtomic(
                        reply, (short) 0,
                        apdu.getBuffer(), (short) 0,
                        (short) reply.length);
                    apdu.setOutgoingAndSend((short) 0, (short) reply.length);
                    break;
                }
                case CLA_KEY_AGREEMENT: {
                    secureChannelManagerOnCard.processKeyAgreement(apdu);
                    break;
                }
                case CLA_ENCRYPTED: {
                    if (!secureChannelManagerOnCard.isSecureChannelEstablished()) {
                        // count incorrect counter and consider blocking the card
                        // we cannot encrypt without successful key agreement first
                        throw new EmeraldProtocolException();
                    }
                    // encrypted communication using secure channel after successful ECDH
                    short dataLength = apdu.setIncomingAndReceive();
                    final short offsetCommandData = apdu.getOffsetCdata();
                    // decrypt incoming message
                    byte[] plaintext = secureChannelManagerOnCard.decrypt(apduBuffer, offsetCommandData, dataLength);

                    // forward decrypted message to SubApplet
                    byte[] responsePlaintext = passwordManagerSubApplet.process(plaintext);

                    // encrypt outgoing message and send
                    byte[] responseCiphertext = secureChannelManagerOnCard.encrypt(responsePlaintext);
                    Util.arrayCopyNonAtomic(responseCiphertext, (short) 0,
                        apduBuffer, offsetCommandData, (short) responseCiphertext.length);
                    apdu.setOutgoingAndSend(offsetCommandData, (short) responseCiphertext.length);
                    break;
                }

                default: {
                    // unknown APDU class
                    break;
                }
            }
        }catch (EmeraldProtocolException e){
            // possible attack, security alert
            // decrement security alert countdown or block the card if countdown is depleted
            if(securityAlertCountdown > 0){
                securityAlertCountdown--;
                // empty response
                apdu.setOutgoingAndSend((short) 0, (short) 0);
            }
            else {
                isAppletBlocked = true;
                respondAppletBlocked(apdu);
            }
        }

    }

    public void respondAppletBlocked(APDU apdu){
        byte[] apduBuffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(APDU_APPLET_BLOCKED, (short)0, apduBuffer, (short)0,
            (short) APDU_APPLET_BLOCKED.length);
        apdu.setOutgoingAndSend((short)0, (short) APDU_APPLET_BLOCKED.length);
    }

    @Override
    public boolean select() {
        clearSessionData();
        return true;
    }

    @Override
    public void deselect() {
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
     * @see #deselect()
     */
    private void clearSessionData() {
        secureChannelManagerOnCard.clearSessionData();
    }
}
