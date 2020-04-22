package jpake;

import java.math.BigInteger;

import applet.ZKPPayload;
import javacard.framework.Util;
import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;

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
        byte[] output = new byte[(short)(1+senderID.length+1+encA.length+1+
                                 encPublicA.length+1+encPublicV.length+1+encResult.length)];
        short currStart = 0;
        // TODO: Using System.arrayCopy until exception bug with arrayCopyNonAtomic is fixed
        output[currStart] = (byte)senderID.length;
        currStart +=1;
        Util.arrayCopyNonAtomic(senderID, (short)0, output, currStart, (short)senderID.length);
        //System.arraycopy(senderID, (int)0, output, currStart, senderID.length);
        currStart += senderID.length;
        output[currStart] = (byte)encA.length;
        currStart += 1;
        //System.arraycopy(encA, (int) 0, output, currStart, encA.length);
        Util.arrayCopyNonAtomic(encA, (short) 0, output, currStart, (short)encA.length);
        currStart += encA.length;
        output[currStart] = (byte)encPublicA.length;
        currStart += 1;
        //System.arraycopy(encPublicA, (int) 0, output, currStart, encPublicA.length);
        Util.arrayCopyNonAtomic(encPublicA, (short) 0, output, currStart, (short)encPublicA.length);
        currStart += encPublicA.length;
        output[currStart] = (byte)encPublicV.length;
        currStart += 1;
        //System.arraycopy(encPublicV, (int) 0, output, currStart, encPublicV.length);
        Util.arrayCopyNonAtomic(encPublicV, (short) 0, output, currStart, (short)encPublicV.length);
        currStart += encPublicV.length;
        output[currStart] = (byte)encResult.length;
        currStart += 1;
        //System.arraycopy(encResult, (int) 0, output, currStart, encResult.length);
        Util.arrayCopyNonAtomic(encResult, (short) 0, output, currStart, (short)encResult.length);
        currStart += encResult.length;
        return output;
    }

    public static jpakeActiveSecondPayload fromBytes(byte[] input){
        //TODO: replace all Array.copyOfRange to arrayCopyNonAtomic when fixed
        short currStart = 0;
        byte senderIDlen = input[currStart];
        currStart += 1;

        byte[] senderID = new byte[senderIDlen];
        Util.arrayCopyNonAtomic(input,currStart,senderID,(short)0,(short)senderIDlen);
        //byte[] senderID = Arrays.copyOfRange(input,currStart,currStart+senderIDlen);
        currStart += senderIDlen;
        byte encAlen = input[currStart];
        currStart += 1;
        byte[] encA = new byte[encAlen];
        Util.arrayCopyNonAtomic(input, currStart, encA, (short)0, (short)encAlen);
        ECPoint A = jpakeActor.curve.decodePoint(encA);
        //ECPoint A = jpakeActor.curve.decodePoint(Arrays.copyOfRange(input, currStart, currStart+encAlen));
        currStart += encAlen;
        byte encPublicAlen = input[currStart];
        currStart += 1;
        byte[] encPublicA = new byte[encPublicAlen];
        Util.arrayCopyNonAtomic(input, currStart, encPublicA, (short)0, (short)encPublicAlen);
        ECPoint publicA = jpakeActor.curve.decodePoint(encPublicA);
        //ECPoint publicA = jpakeActor.curve.decodePoint(Arrays.copyOfRange(input, currStart, currStart+encPublicAlen));
        currStart += encPublicAlen;
        byte encPublicVlen = input[currStart];
        currStart += 1;
        byte[] encPublicV = new byte[encPublicVlen];
        Util.arrayCopyNonAtomic(input, currStart, encPublicV, (short)0, (short)encPublicVlen);
        ECPoint publicV = jpakeActor.curve.decodePoint(encPublicV);
        //ECPoint publicV = jpakeActor.curve.decodePoint(Arrays.copyOfRange(input, currStart, currStart+encPublicVlen));
        currStart += encPublicVlen;
        byte encResultlen = input[currStart];
        currStart += 1;
        byte[] encResult = new byte[encResultlen];
        Util.arrayCopyNonAtomic(input, currStart, encResult, (short)0, (short)encResultlen);
        BigInteger result = new BigInteger(encResult);
        //BigInteger result = new BigInteger(Arrays.copyOfRange(input, currStart, currStart+encResultlen));

        ZKPPayload zkpx2s = new ZKPPayload(publicA, publicV, result);
        return new jpakeActiveSecondPayload(senderID, A, zkpx2s);
    }
}
