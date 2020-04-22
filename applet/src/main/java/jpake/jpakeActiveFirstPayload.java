/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpake;

import applet.EmIllegalArgumentException;
import applet.ZKPPayload;

import java.math.BigInteger;

import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;

import org.bouncycastle.math.ec.ECPoint;

public final class jpakeActiveFirstPayload {
    private final byte[] senderID;
    private final ECPoint G1;
    private final ECPoint G2;
    private final ZKPPayload ZKPx1;
    private final ZKPPayload ZKPx2;

    public jpakeActiveFirstPayload(byte[] id, ECPoint G1, ECPoint G2, ZKPPayload ZKPx1, ZKPPayload ZKPx2){
        if(G1 == null || G2 == null || ZKPx1 == null || ZKPx2 == null){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        senderID = id;
        this.G1 = G1;
        this.G2 = G2;
        this.ZKPx1 = ZKPx1;
        this.ZKPx2 = ZKPx2;
    }

    public byte[] getSenderID() {
        return this.senderID;
    }

    public ECPoint getG1() {
        return this.G1;
    }
    public ECPoint getG2() {
        return this.G2;
    }
    public ZKPPayload getZKPx1() {
        return this.ZKPx1;
    }
    public ZKPPayload getZKPx2() {
        return this.ZKPx2;
    }

    public byte[] toBytes(){
        byte[] encodedG1 = G1.getEncoded(false);
        byte[] encodedG2 = G2.getEncoded(false);
        byte[] publicA1Encoded = ZKPx1.getPublicA().getEncoded(false);
        byte[] publicV1Encoded = ZKPx1.getPublicV().getEncoded(false);
        byte[] result1 = ZKPx1.getResult().toByteArray();
        byte[] publicA2Encoded = ZKPx2.getPublicA().getEncoded(false);
        byte[] publicV2Encoded = ZKPx2.getPublicV().getEncoded(false);
        byte[] result2 = ZKPx2.getResult().toByteArray();
        byte[] output = new byte[(short)(1+senderID.length+1+encodedG1.length+1
                                         +encodedG2.length+1+publicA1Encoded.length+1
                                         +publicV1Encoded.length+1+result1.length+1
                                         +publicA2Encoded.length+1+publicV2Encoded.length+1+result2.length)];
        short currStart = 0;
        output[currStart] = (byte)senderID.length;
        currStart +=1;
        Util.arrayCopyNonAtomic(senderID, (short)0, output, currStart, (short)senderID.length);
        currStart += senderID.length;
        output[currStart] = (byte)encodedG1.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encodedG1, (short) 0, output, currStart,(short)encodedG1.length);
        currStart += encodedG1.length;
        output[currStart] = (byte)encodedG2.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encodedG2, (short) 0, output, currStart,(short)encodedG2.length);
        currStart += encodedG2.length;
        output[currStart] = (byte)publicA1Encoded.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(publicA1Encoded, (short) 0, output, currStart,(short)publicA1Encoded.length);
        currStart += publicA1Encoded.length;
        output[currStart] = (byte)publicV1Encoded.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(publicV1Encoded, (short) 0, output, currStart,(short)publicV1Encoded.length);
        currStart += publicV1Encoded.length;
        output[currStart] = (byte)result1.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(result1, (short) 0, output, currStart,(short)result1.length);
        currStart += result1.length;
        output[currStart] = (byte)publicA2Encoded.length;
        currStart +=1;
        Util.arrayCopyNonAtomic(publicA2Encoded, (short) 0, output, currStart,(short)publicA2Encoded.length);
        currStart += publicA2Encoded.length;
        output[currStart] = (byte) publicV2Encoded.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(publicV2Encoded, (short) 0, output, currStart,(short)publicV2Encoded.length);
        currStart += publicV2Encoded.length;
        output[currStart] = (byte)result2.length;
        currStart +=1;
        Util.arrayCopyNonAtomic(result2, (short) 0, output, currStart,(short)result2.length);
        return output;
    }

    public static jpakeActiveFirstPayload fromBytes(byte[] input) throws EmIllegalArgumentException, IllegalArgumentException, ArrayIndexOutOfBoundsException, NullPointerException, SystemException
    {
        short currStart = 0;
        short senderIDlen = input[currStart];
        currStart += 1;
        byte[] senderID = new byte[senderIDlen];
        Util.arrayCopyNonAtomic(input,currStart,senderID,(short)0,senderIDlen);
        currStart += senderIDlen;
        short encG1len = input[currStart];
        currStart += 1;
        byte[] encG1 = new byte[encG1len];
        Util.arrayCopyNonAtomic(input, currStart, encG1, (short)0, encG1len);
        ECPoint G1 = jpakeActor.curve.decodePoint(encG1);
        currStart += encG1len;
        short encG2len = input[currStart];
        currStart += 1;
        byte[] encG2 = new byte[encG2len];
        Util.arrayCopyNonAtomic(input, currStart, encG2, (short)0, encG2len);
        ECPoint G2 = jpakeActor.curve.decodePoint(encG2);
        currStart += encG2len;
        short pubA1len = input[currStart];
        currStart += 1;
        byte[] encPublicA1 = new byte[pubA1len];
        Util.arrayCopyNonAtomic(input, currStart, encPublicA1, (short)0, pubA1len);
        ECPoint publicA1 = jpakeActor.curve.decodePoint(encPublicA1);
        currStart += pubA1len;
        short pubV1len = input[currStart];
        currStart += 1;
        byte[] encPublicV1 = new byte[pubV1len];
        Util.arrayCopyNonAtomic(input, currStart, encPublicV1, (short)0, pubV1len);
        ECPoint publicV1 = jpakeActor.curve.decodePoint(encPublicV1);
        currStart += pubV1len;
        short result1len = input[currStart];
        currStart += 1;
        byte[] encResult1 = new byte[result1len];
        Util.arrayCopyNonAtomic(input, currStart, encResult1, (short)0, result1len);
        BigInteger result1 =  new BigInteger(encResult1);
        currStart += result1len;
        short pubA2len = input[currStart];
        currStart += 1;
        byte[] encPublicA2 = new byte[pubA2len];
        Util.arrayCopyNonAtomic(input, currStart, encPublicA2, (short)0, pubA2len);
        ECPoint publicA2 = jpakeActor.curve.decodePoint(encPublicA2);
        currStart += pubA2len;
        short pubV2len = input[currStart];
        currStart += 1;
        byte[] encPublicV2 = new byte[pubV2len];
        Util.arrayCopyNonAtomic(input, currStart, encPublicV2, (short)0, pubV2len);
        ECPoint publicV2 = jpakeActor.curve.decodePoint(encPublicV2);
        currStart += pubV2len;
        short result2len = input[currStart];
        currStart += 1;
        byte[] encResult2 = new byte[result2len];
        Util.arrayCopyNonAtomic(input, currStart, encResult2, (short)0, result2len);
        BigInteger result2 =  new BigInteger(encResult2);
        if(input.length != currStart+result2len){
            throw new EmIllegalArgumentException();
        }
        ZKPPayload zkpx1 = new ZKPPayload(publicA1, publicV1, result1);
        ZKPPayload zkpx2 = new ZKPPayload(publicA2, publicV2, result2);
        return new jpakeActiveFirstPayload(senderID,G1,G2,zkpx1,zkpx2);
    }

}
