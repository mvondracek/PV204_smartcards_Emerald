/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpake;

import java.math.BigInteger;
import java.security.SecureRandom;
import javacard.security.CryptoException;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;

/*
Abstract class with common functionality for JPAKE protocol participants.
We use three-pass version of the protocol, so the main functionality is divided
between two children classes
*/
public abstract class jpakeActor {

    protected ECNamedCurveParameterSpec curvespec = ECNamedCurveTable.getParameterSpec("curve25519");
    protected ECPoint G = curvespec.getG();   /*subgroup generator*/
    protected BigInteger n = curvespec.getN(); /*order of subrgoup*/
    protected byte[] userID;
    protected BigInteger pinKey;

    protected BigInteger x1;
    protected BigInteger x2;
    protected ECPoint G1;
    protected ECPoint G2;
    protected ECPoint G1_recv;
    protected ECPoint G2_recv;
    protected ECPoint A_recv;

    public jpakeActor(byte[] userID, byte[] pinKey){
        if(userID.length ==0 || pinKey.length == 0){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.userID = userID;
        this.pinKey = new BigInteger(pinKey);
    }

    public ECPoint computeCommonKey()
    {
        return A_recv.subtract(G2_recv.multiply(x2.multiply(pinKey).mod(n))).multiply(x2);
    }
}
