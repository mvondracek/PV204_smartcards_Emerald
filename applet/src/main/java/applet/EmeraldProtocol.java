/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

public class EmeraldProtocol {
    public static final byte CLA_PLAINTEXT = (byte) 0x01;
    public static final byte CLA_ENCRYPTED = (byte) 0xEE;

    public static final byte MESSAGE_HEADER_LENGTH = 3;
    public static final byte PASSWORD_SLOT_LENGTH = 29;
    public static final byte PASSWORD_SLOTS_COUNT = 3;
    public static final byte MESSAGE_LENGTH = MESSAGE_HEADER_LENGTH + PASSWORD_SLOT_LENGTH;

    /**
     * Offset of message type (byte) in decrypted data.
     */
    public static final byte MESSAGE_TYPE_OFFSET = (byte) 0;
    /**
     * Offset of password slot identification number.
     * Used to select slot and then set or get password.
     */
    public static final byte PASSWORD_SLOT_ID_OFFSET = (byte) 1;
    /**
     * Offset of byte with length of transmitted password.
     * Used to set/get password to/from password manager applet.
     */
    public static final byte PASSWORD_LENGTH_OFFSET = (byte) 2;
    /**
     * Offset of password value.
     * Used to set/get password to/from password manager applet.
     */
    public static final byte PASSWORD_VALUE_OFFSET = (byte) 3;

    /**
     * Message from PC to card with intent to set password to selected slot.
     */
    public static final byte MESSAGE_SET_PASSWORD = (byte) 0x5E;
    /**
     * Message from card to PC confirming that password was set to selected slot.
     */
    public static final byte MESSAGE_OK_SET = (byte) 0x50;
    /**
     * Message from PC to card with intent to get password from selected slot.
     */
    public static final byte MESSAGE_GET_PASSWORD = (byte) 0x6E;
    /**
     * Message from card to PC delivering requested password from selected slot.
     */
    public static final byte MESSAGE_OK_GET = (byte) 0x60;

    // TODO we use static AES key until J-PAKE is implemented
    public static final byte[] aesKeyDevelopmentTODO = new byte[]{ // TODO replace with J-PAKE
        (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE, (byte) 0x22,
        (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFE, (byte) 0xED, (byte) 0xC0, (byte) 0xFF,
        (byte) 0xEE, (byte) 0x22, (byte) 0xC0, (byte) 0xDE, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00};

    private EmeraldProtocol() {
        // Constant storage class
        throw new EmIllegalStateException();
    }
}
