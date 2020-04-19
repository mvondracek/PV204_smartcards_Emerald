/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */
package tests;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class EmeraldAppletTest extends BaseTest {
    @Test
    public void exampleTest() throws Exception {
        final ResponseAPDU responseAPDU = connect().transmit(new CommandAPDU(0x01, 0x02, 0x03, 0x04));
        Assert.assertNotNull(responseAPDU);
        Assert.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, responseAPDU.getData());
    }
}
