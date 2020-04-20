/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */
package e2e;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import tests.BaseTest;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static cardTools.Util.prepareParameterData;


/**
 * End-to-End tests for {@link applet.EmeraldApplet} based on APDU communication with applet
 * instance (by default in simulator).
 */
public class EmeraldAppletAPDUTest extends BaseTest {
    private static final byte[] TEST_PIN = new byte[]{1, 2, 3, 4};
    private static final byte[] PARAMETER_DATA = prepareParameterData(
        APPLET_AID_BYTE, new byte[0], TEST_PIN);

    @Test
    public void exampleTest() throws Exception {
        final ResponseAPDU responseAPDU = connect(PARAMETER_DATA).transmit(
            new CommandAPDU(0x01, 0x02, 0x03, 0x04));
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, responseAPDU.getData());
    }
}
