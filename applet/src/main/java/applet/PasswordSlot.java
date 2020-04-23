/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import javacard.framework.Util;

/**
 * Slot for storing password.
 * Works as an array with fixed maximum size allocated in constructor. If stored password is shorter
 * than allowed capacity, password length is stored so that it can be correctly retrieved without
 * remembering its length elsewhere.
 */
public class PasswordSlot {
    private final byte[] buffer;
    private byte length = 0;

    public PasswordSlot(byte capacity) {
        buffer = new byte[capacity];
    }

    /**
     * Set password from provided source array.
     *
     * @param src       source array
     * @param srcOffset offset of password in source array
     * @param length    length of password in source array
     */
    public void setPassword(byte[] src, short srcOffset, byte length) {
        if (length > buffer.length) {
            throw new EmIllegalArgumentException();
        }
        Util.arrayCopyNonAtomic(src, srcOffset, buffer, (short) 0, length);
        this.length = length;
    }

    /**
     * Copy password to provided destination array.
     *
     * @param dst       destination array
     * @param dstOffset offset of password in destination array
     * @return length of password copied to destination array
     */
    public short getPassword(byte[] dst, short dstOffset) {
        Util.arrayCopyNonAtomic(buffer, (short) 0, dst, dstOffset, length);
        return length;
    }

    /**
     * Get length of currently stored password.
     */
    public byte getPasswordLength() {
        return length;
    }

    /**
     * Get maximum allowed length of password that this slot can store.
     */
    public byte getPasswordLengthCapacity() {
        return (byte) buffer.length;
    }
}
