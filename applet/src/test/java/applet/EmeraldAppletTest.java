/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */
package applet;

import cardTools.Util;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import static cardTools.Util.prepareParameterData;


/**
 * Unit tests for {@link applet.EmeraldApplet}.
 */
class EmeraldAppletTest {
    public static final byte[] TEST_AID = Util.hexStringToByteArray("FEEDC0FFEE22C0DE");

    @Test
    void installPINMissing() {
        byte[] testPin = new byte[0];
        byte[] parameterData = prepareParameterData(TEST_AID, new byte[0], testPin);
        try {
            EmeraldApplet.install(parameterData, (byte) 0, (byte) parameterData.length);
            Assert.fail("Expected IllegalArgumentException to be thrown.");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    void installPINWrongDigitNegative() {
        byte[] testPin = new byte[]{0, -1, 0, 0};
        byte[] parameterData = prepareParameterData(TEST_AID, new byte[0], testPin);
        try {
            EmeraldApplet.install(parameterData, (byte) 0, (byte) parameterData.length);
            Assert.fail("Expected IllegalArgumentException to be thrown.");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    void installPINWrongDigitLarger() {
        byte[] testPin = new byte[]{0, 0, 11, 0};
        byte[] parameterData = prepareParameterData(TEST_AID, new byte[0], testPin);
        try {
            EmeraldApplet.install(parameterData, (byte) 0, (byte) parameterData.length);
            Assert.fail("Expected IllegalArgumentException to be thrown.");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    void installPINShort() {
        byte[] testPin = new byte[]{0, 0, 0};
        byte[] parameterData = prepareParameterData(TEST_AID, new byte[0], testPin);
        try {
            EmeraldApplet.install(parameterData, (byte) 0, (byte) parameterData.length);
            Assert.fail("Expected IllegalArgumentException to be thrown.");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    void installPINLong() {
        byte[] testPin = new byte[]{0, 0, 0, 0, 0};
        byte[] parameterData = prepareParameterData(TEST_AID, new byte[0], testPin);
        try {
            EmeraldApplet.install(parameterData, (byte) 0, (byte) parameterData.length);
            Assert.fail("Expected IllegalArgumentException to be thrown.");
        } catch (IllegalArgumentException ignored) {
        }
    }
}
