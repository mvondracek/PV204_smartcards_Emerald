/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;

public class EmeraldApplet extends Applet implements MultiSelectable {
    public static final byte PIN_LENGTH = 4;

    /**
     * Persistent PIN storage in EEPROM.
     * TODO `javacard.framework.OwnerPIN` is not suitable as we need to read PIN value for J-PAKE
     */
    private final byte[] pin; // TODO store pin securely


    /**
     * Create instance of the applet.
     *
     * <p>Should be used from {@link #install} method. See {@link #install} for description of
     * parameters. Calls {@link #register()} on successful initialization.
     */
    EmeraldApplet(byte[] bArray, short bOffset, byte bLength) {
        byte instanceAIDLength = bArray[bOffset];
        byte controlInfoLength = bArray[bOffset + 1 + instanceAIDLength];
        byte appletDataLength = bArray[bOffset + 1 + instanceAIDLength + 1 + controlInfoLength];

        short appletDataOffset = (short) (bOffset + 1 + instanceAIDLength + 1 + controlInfoLength + 1);
        // first byte of applet data:
        // bArray[bOffset + 1 + instanceAIDLength + 1 + controlInfoLength + 1]
        // last byte of applet data:
        // bArray[bOffset + 1 + instanceAIDLength + 1 + controlInfoLength + 1 + appletDataLength - 1]

        // check if we have received PIN
        if (appletDataLength != PIN_LENGTH) {
            throw new IllegalArgumentException(
                String.format("Unexpected length of applet data, expected=%s, actual=%s",
                    PIN_LENGTH, appletDataLength));
        }
        // check if bytes of received PIN are only digits <0;9>
        for (int i = 0; i < PIN_LENGTH; i++) {
            byte pinDigit = bArray[appletDataOffset + i];
            if (!(0 <= pinDigit && pinDigit <= 9)) {
                throw new IllegalArgumentException(
                    String.format("Byte value of PIN digit not in range <0;9>, actual=%d", pinDigit));
            }
        }

        // create persistent pin in EEPROM
        pin = new byte[PIN_LENGTH];
        Util.arrayCopy(bArray, appletDataOffset, pin, (short) 0, PIN_LENGTH);

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
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EmeraldApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        byte[] reply = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        Util.arrayCopyNonAtomic(
            reply, (short) 0,
            apdu.getBuffer(), (short) 0,
            (short) reply.length);
        apdu.setOutgoingAndSend((short) 0, (short) reply.length);
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
