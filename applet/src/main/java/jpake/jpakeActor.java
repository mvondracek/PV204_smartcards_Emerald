/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpake;

import applet.EmIllegalArgumentException;
import applet.EmIllegalStateException;
import java.math.BigInteger;
import java.security.SecureRandom;

import javacard.security.MessageDigest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/*
Abstract class with common functionality for JPAKE protocol participants.
We use three-pass version of the protocol, so the main functionality is divided
between two children classes
*/
public abstract class jpakeActor {

    protected static ECNamedCurveParameterSpec curvespec = ECNamedCurveTable.getParameterSpec("curve25519");
    protected static ECPoint G = curvespec.getG();   /*subgroup generator*/
    protected static BigInteger n = curvespec.getN(); /*order of subrgoup*/
    protected static BigInteger coFactor = curvespec.getH();
    protected byte[] userID;

    /**
     * Persistent PIN storage in EEPROM.
     * NOTE: `javacard.framework.OwnerPIN` is not suitable as we need to read PIN value for J-PAKE
     */
    protected BigInteger pinKey;

    public static ECCurve curve = curvespec.getCurve();

    protected BigInteger x1;
    protected BigInteger x2;
    protected ECPoint G1;
    protected ECPoint G2;
    protected ECPoint G1_recv;
    protected ECPoint G2_recv;
    protected ECPoint A_recv;

    public jpakeActor(byte[] userID, byte[] pinKey){
        if(userID.length ==0 || pinKey.length == 0){
            throw new EmIllegalStateException();
        }
        //here we need to check that pin-derived key isn't all zero
        //otherwise EC cryptomagic won't work
        boolean isAllZero = true;
        for( int i = 0; i < pinKey.length && isAllZero; ++i ){
            if( pinKey[i] != 0 ) {isAllZero = false;}
        }
        if(isAllZero){
            throw new EmIllegalArgumentException();
        }
        this.userID = userID;
        this.pinKey = new BigInteger(pinKey);
    }

    private ECPoint computeCommonKey()
    {
        return A_recv.subtract(G2_recv.multiply(x2.multiply(pinKey).mod(n))).multiply(x2);
    }

    public byte[] derivePlainCommonKey(){
        ECPoint p = computeCommonKey();
        byte[] pEncoded = p.getEncoded(false);
        //will use SHA-256 instead of SHA-512 to avoid array copy operation
        MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        byte[] outputBytes = new byte[dig.getLength()];
        dig.doFinal(pEncoded, (short) 0, (short) pEncoded.length, outputBytes, (short) 0);
        return outputBytes;
    }

    public void clearSessionData(){
        //rewrite private members with random data
        x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        BigInteger r1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        BigInteger r2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        G1 = curve.createPoint(r1, r2);
        r1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        r2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        G2 = curve.createPoint(r1, r2);
        r1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        r2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        G1_recv = curve.createPoint(r1, r2);
        r1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        r2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        G2_recv = curve.createPoint(r1, r2);
        r1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        r2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        A_recv = curve.createPoint(r1, r2);
    }
}
