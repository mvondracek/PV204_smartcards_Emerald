/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;
import applet.jcmathlib.ECConfig;
import applet.jcmathlib.ECPoint;
import applet.jcmathlib.ECCurve;
import applet.jcmathlib.SecP256r1;

public class EmeraldApplet extends Applet implements MultiSelectable {
    public static final byte PIN_LENGTH = 4;

    /**
     * Persistent PIN storage in EEPROM.
     * TODO `javacard.framework.OwnerPIN` is not suitable as we need to read PIN value for J-PAKE
     */
    private final byte[] pin; // TODO store pin securely

    //region TODO example use of JCMathlib
    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         point1 = null;
    ECPoint         point2 = null;
    final static byte[] ECPOINT_TEST_VALUE = {(byte)0x04, (byte) 0x3B, (byte) 0xC1, (byte) 0x5B, (byte) 0xE5, (byte) 0xF7, (byte) 0x52, (byte) 0xB3, (byte) 0x27, (byte) 0x0D, (byte) 0xB0, (byte) 0xAE, (byte) 0xF2, (byte) 0xBC, (byte) 0xF0, (byte) 0xEC, (byte) 0xBD, (byte) 0xB5, (byte) 0x78, (byte) 0x8F, (byte) 0x88, (byte) 0xE6, (byte) 0x14, (byte) 0x32, (byte) 0x30, (byte) 0x68, (byte) 0xC4, (byte) 0xC4, (byte) 0x88, (byte) 0x6B, (byte) 0x43, (byte) 0x91, (byte) 0x4C, (byte) 0x22, (byte) 0xE1, (byte) 0x67, (byte) 0x68, (byte) 0x3B, (byte) 0x32, (byte) 0x95, (byte) 0x98, (byte) 0x31, (byte) 0x19, (byte) 0x6D, (byte) 0x41, (byte) 0x88, (byte) 0x0C, (byte) 0x9F, (byte) 0x8C, (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86, (byte) 0x1A, (byte) 0x86, (byte) 0xF8, (byte) 0x0D, (byte) 0x01, (byte) 0x46, (byte) 0x0C, (byte) 0xB5, (byte) 0x8D, (byte) 0x86, (byte) 0x6C, (byte) 0x09};
    final static byte[] SCALAR_TEST_VALUE = {(byte) 0xE8, (byte) 0x05};
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

        //region TODO example use of JCMathlib
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256);
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        point1 = new ECPoint(curve, ecc.ech);
        point2 = new ECPoint(curve, ecc.ech);
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
        byte[] reply = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        //region TODO example use of JCMathlib
        point1.randomize(); // Generate first point at random
        point2.randomize();
        // point2.setW(ECPOINT_TEST_VALUE, (short) 0, (short) ECPOINT_TEST_VALUE.length); // Set second point to predefined value
        point1.add(point2); // Add two points together

        // TODO BUG mvondracek: `ECPoint#multiplication` hangs in `applet.jcmathlib.Bignat.sqrt_FP`
        //      on line 1738 in while loop. Is that simulator or computer specific?
        //      point1.multiplication(SCALAR_TEST_VALUE, (short) 0, (short) SCALAR_TEST_VALUE.length);
        //      byte[] test_scalar = new byte[]{(byte)2};
        //      point1.multiplication(test_scalar, (short) 0, (short) test_scalar.length);

        //endregion

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
        //region TODO example use of JCMathlib
        ecc.refreshAfterReset();
        //endregion
    }
}
