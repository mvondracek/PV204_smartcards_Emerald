/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpakeactor;

import jpakeR1Msg.jpakeR1Msg;
import java.math.BigInteger;
import java.security.SecureRandom;
import javacard.security.*; 
import javacard.security.CryptoException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;

public class JPAKEActor {
    
    private ECNamedCurveParameterSpec curvespec = ECNamedCurveTable.getParameterSpec("curve25519");
    private ECPoint G = curvespec.getG();   /*subgroup generator*/
    private BigInteger n = curvespec.getN(); /*order of subrgoup*/
    private byte[] userID;
    private byte[] pinKey;
    
    private BigInteger x1;
    private BigInteger x2;
    private ECPoint G1;
    private ECPoint G2;
    private ECPoint G3;
    private ECPoint G4;
    
    private ACTOR_STATUS status;
    
    public enum ACTOR_STATUS {AS_INIT, AS_R1_PREPARED, AS_R2_PREPARED, AS_R1_VERIFIED, AS_R2_VERIFIED, AS_KEY_DERIVED
    }
    
    public JPAKEActor(byte[] userID, byte[] pinKey){
        this.userID = userID;
        this.pinKey = pinKey;
        this.status = ACTOR_STATUS.AS_INIT;
    }
    
    public jpakeR1Msg prepareR1Data(){
        //creating two private keys in range [1, n-1]
        x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        //computing public values to be sent
        G1 = G.multiply(x1);
        G2 = G.multiply(x2);
        
        //TODO: next we need to calculate ZKP
        BigInteger ZKP1 = BigIntegers.ZERO;
        BigInteger ZKP2 = BigIntegers.ZERO;
        
        this.status = ACTOR_STATUS.AS_R1_PREPARED;
        return new jpakeR1Msg(G1,G2,ZKP1,ZKP2);
    }
    
    public void proceedR1Data()
    {
          //TODO: initialize G3, G4
          //TODO: verify ZKP, if no, then throw exception 
        this.status=ACTOR_STATUS.AS_R1_VERIFIED;
    }
    public void prepareR2Data()
    {
        if(this.status != ACTOR_STATUS.AS_R1_VERIFIED)
            throw new CryptoException(CryptoException.INVALID_INIT);
        
        ECPoint Gsum = G1.add(G3).add(G4);
        BigInteger biPinKey = new BigInteger(this.pinKey);
        ECPoint A = Gsum.multiply(x2.multiply(new BigInteger(this.pinKey)));
        //TODO: obtain ZKP value and construct a payload
        //return new jpakeR2Msg(Gsum, ZKP_secret);
    }

}
