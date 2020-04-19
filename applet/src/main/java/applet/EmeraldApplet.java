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
    public EmeraldApplet(byte[] buffer, short offset, byte length) {
        register();
    }

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
        return true;
    }

    @Override
    public boolean select(boolean appInstAlreadyActive) {
        return true;
    }

    @Override
    public void deselect() {
    }

    @Override
    public void deselect(boolean appInstAlreadyActive) {
    }
}
