/*
This file was merged and modified based on "JavaCard Template project with
Gradle" which was published under MIT license included below.
https://github.com/crocs-muni/javacard-gradle-template-edu

License from 2020-04-18 https://github.com/crocs-muni/javacard-gradle-template-edu/blob/ebcb012a192092678eb9b7f198be5a6a26136f31/LICENSE
~~~
The MIT License (MIT)

Copyright (c) 2015 Dusan Klinec, Martin Paljak, Petr Svenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
~~~
*/

package emcardtools;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Util {

    public static String toHex(byte[] bytes) {
        return toHex(bytes, 0, bytes.length);
    }

    public static String toHex(byte[] bytes, int offset, int len) {
        StringBuilder result = new StringBuilder();

        for (int i = offset; i < offset + len; i++) {
            result.append(String.format("%02X", bytes[i]));
        }

        return result.toString();
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        String sanitized = s.replace(" ", "");
        byte[] b = new byte[sanitized.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(sanitized.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }


    // Utils
    public static short getShort(byte[] buffer, int offset) {
        return ByteBuffer.wrap(buffer, offset, 2).order(ByteOrder.BIG_ENDIAN).getShort();
    }

    public static short readShort(byte[] data, int offset) {
        return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
    }

    public static byte[] shortToByteArray(int s) {
        return new byte[]{(byte) ((s & 0xFF00) >> 8), (byte) (s & 0x00FF)};
    }


    public static byte[] joinArray(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        final byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static byte[] trimLeadingZeroes(byte[] array) {
        short startOffset = 0;
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0) {
                break;
            } else {
                // still zero
                startOffset++;
            }
        }

        byte[] result = new byte[array.length - startOffset];
        System.arraycopy(array, startOffset, result, 0, array.length - startOffset);
        return result;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] tmp_conc = concat(a, b);
        return concat(tmp_conc, c);

    }

    /**
     * Prepare parameter data for applet installation from provided components.
     */
    public static byte[] prepareParameterData(byte[] aid, byte[] controlInfo, byte[] appletData) {
        int parameterDataLength = 1 + aid.length + 1 + controlInfo.length + 1 + appletData.length;
        int maximumParameterDataLength = 127;
        if (parameterDataLength > maximumParameterDataLength) {
            throw new IllegalArgumentException(
                String.format("Maximum parameter data length exceeded, max=%d, actual=%d",
                    maximumParameterDataLength, parameterDataLength));
        }
        int AIDOffset = 1;
        int controlInfoOffset = AIDOffset + aid.length + 1;
        int appletDataOffset = controlInfoOffset + controlInfo.length + 1;
        byte[] parameterData = new byte[parameterDataLength];
        parameterData[AIDOffset - 1] = (byte) aid.length;
        System.arraycopy(aid, 0, parameterData, AIDOffset, aid.length);
        parameterData[controlInfoOffset - 1] = (byte) controlInfo.length;
        System.arraycopy(controlInfo, 0, parameterData, controlInfoOffset, controlInfo.length);
        parameterData[appletDataOffset - 1] = (byte) appletData.length;
        System.arraycopy(appletData, 0, parameterData, appletDataOffset, appletData.length);
        return parameterData;
    }
}
