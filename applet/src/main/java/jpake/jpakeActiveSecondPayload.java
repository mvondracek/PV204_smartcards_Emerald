package jpake;

import applet.EmIllegalArgumentException;
import applet.ZKPPayload;

import java.math.BigInteger;

import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;

import org.bouncycastle.math.ec.ECPoint;

public final class jpakeActiveSecondPayload {
    private final byte[] senderID;
    private final ECPoint A;
    private final ZKPPayload ZKPx2s;

    public jpakeActiveSecondPayload(byte[] id, ECPoint A, ZKPPayload ZKPx2s){
        if(A == null || ZKPx2s == null){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.senderID = id;
        this.A = A;
        this.ZKPx2s = ZKPx2s;
    }

    public byte[] getSenderID() {
        return this.senderID;
    }

    public ECPoint getA() {
        return this.A;
    }
    public ZKPPayload getZKPx2s() {
        return this.ZKPx2s;
    }
    public byte[] toBytes(){
        byte[] encA = A.getEncoded(false);
        byte[] encPublicA = ZKPx2s.getPublicA().getEncoded(false);
        byte[] encPublicV = ZKPx2s.getPublicV().getEncoded(false);
        byte[] encResult = getZKPx2s().getResult().toByteArray();
        byte[] output = new byte[(short)(1+senderID.length+1+encA.length+1
                                 +encPublicA.length+1+encPublicV.length+1+encResult.length)];
        short currStart = 0;
        output[currStart] = (byte)senderID.length;
        currStart +=1;
        Util.arrayCopyNonAtomic(senderID, (short)0, output, currStart, (short)senderID.length);
        currStart += senderID.length;
        output[currStart] = (byte)encA.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encA, (short) 0, output, currStart, (short)encA.length);
        currStart += encA.length;
        output[currStart] = (byte)encPublicA.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encPublicA, (short) 0, output, currStart, (short)encPublicA.length);
        currStart += encPublicA.length;
        output[currStart] = (byte)encPublicV.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encPublicV, (short) 0, output, currStart, (short)encPublicV.length);
        currStart += encPublicV.length;
        output[currStart] = (byte)encResult.length;
        currStart += 1;
        Util.arrayCopyNonAtomic(encResult, (short) 0, output, currStart, (short)encResult.length);
        return output;
    }

    public static jpakeActiveSecondPayload fromBytes(byte[] input) throws EmIllegalArgumentException,IllegalArgumentException, ArrayIndexOutOfBoundsException, NullPointerException, SystemException
    {
        short currStart = 0;
        short senderIDlen = input[currStart];
        currStart += 1;
        byte[] senderID = new byte[senderIDlen];
        Util.arrayCopyNonAtomic(input,currStart,senderID,(short)0,senderIDlen);
        currStart += senderIDlen;
        short encAlen = input[currStart];
        currStart += 1;
        byte[] encA = new byte[encAlen];
        Util.arrayCopyNonAtomic(input, currStart, encA, (short)0, encAlen);
        ECPoint A = jpakeActor.curve.decodePoint(encA);
        currStart += encAlen;
        short encPublicAlen = input[currStart];
        currStart += 1;
        byte[] encPublicA = new byte[encPublicAlen];
        Util.arrayCopyNonAtomic(input, currStart, encPublicA, (short)0, encPublicAlen);
        ECPoint publicA = jpakeActor.curve.decodePoint(encPublicA);
        currStart += encPublicAlen;
        short encPublicVlen = input[currStart];
        currStart += 1;
        byte[] encPublicV = new byte[encPublicVlen];
        Util.arrayCopyNonAtomic(input, currStart, encPublicV, (short)0, encPublicVlen);
        ECPoint publicV = jpakeActor.curve.decodePoint(encPublicV);
        currStart += encPublicVlen;
        short encResultlen = input[currStart];
        currStart += 1;
        byte[] encResult = new byte[encResultlen];
        Util.arrayCopyNonAtomic(input, currStart, encResult, (short)0, encResultlen);
        BigInteger result = new BigInteger(encResult);
        if(input.length != currStart+encResultlen){
            throw new EmIllegalArgumentException();
        }
        ZKPPayload zkpx2s = new ZKPPayload(publicA, publicV, result);
        return new jpakeActiveSecondPayload(senderID, A, zkpx2s);
    }
}
