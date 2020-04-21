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

public class jpakeActor {

    private ECNamedCurveParameterSpec curvespec = ECNamedCurveTable.getParameterSpec("curve25519");
    private ECPoint G = curvespec.getG();   /*subgroup generator*/
    private BigInteger n = curvespec.getN(); /*order of subrgoup*/
    private byte[] userID;
    private BigInteger pinKey;

    private BigInteger x1;
    private BigInteger x2;
    private ECPoint G1;
    private ECPoint G2;
    private ECPoint G1_recv;
    private ECPoint G2_recv;
    private ECPoint A_recv;

    private ACTOR_STATUS status;
    private ACTOR_ROLE role;

    public enum ACTOR_ROLE {AR_ACTIVE, AR_PASSIVE}  //is actor initiating protocol or not
    private enum ACTOR_STATUS {AS_INIT, AS_ACTIVE_FIRST_PAYLOAD_PREPARED,
                              AS_ACTIVE_FIRST_PAYLOAD_VERIFIED, AS_PASSIVE_PAYLOAD_PREPARED,
                              AS_PASSIVE_PAYLOAD_VERIFIED, AS_ACTIVE_SECOND_PAYLOAD_PREPARED,
                              AS_ACTIVE_SECOND_PAYLOAD_VERIFIED, AS_KEY_DERIVED
    }

    public jpakeActor(byte[] userID, ACTOR_ROLE role, byte[] pinKey){
        this.userID = userID;
        this.role = role;
        this.pinKey = new BigInteger(pinKey);
        this.status = ACTOR_STATUS.AS_INIT;
    }

    /* we'll use three-pass variant of the protocol */

    /* this function is called by active side (e.g. reader)*/
    public jpakeActiveFirstPayload activeFirstPayload(){
        //creating two private keys in range [1, n-1]
        x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        //computing public values to be sent
        G1 = G.multiply(x1);
        G2 = G.multiply(x2);

        //TODO: next we need to calculate ZKP for x1 and x2
        BigInteger ZKPx1 = BigIntegers.ZERO;
        BigInteger ZKPx2 = BigIntegers.ZERO;

        this.status = ACTOR_STATUS.AS_ACTIVE_FIRST_PAYLOAD_PREPARED;
        return new jpakeActiveFirstPayload(G1,G2,ZKPx1,ZKPx2);
    }

    public void passiveVerifyActiveFirstPayload(jpakeActiveFirstPayload afpl)
    {
        //TODO: passive verifies ZKP from active's first msg, if no, then throw exception
        this.G1_recv = afpl.getG1();
        this.G2_recv = afpl.getG2();
        this.status=ACTOR_STATUS.AS_ACTIVE_FIRST_PAYLOAD_VERIFIED;
    }

    public jpakePassivePayload passivePayload()
    {
        if(this.status != ACTOR_STATUS.AS_ACTIVE_FIRST_PAYLOAD_VERIFIED)
            throw new CryptoException(CryptoException.INVALID_INIT);

        this.x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        this.x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        this.G1 = G.multiply(x1);
        this.G2 = G.multiply(x2);

        ECPoint B = G1_recv.add(G2_recv.add(G1)).multiply(x2.multiply(pinKey).mod(n));
        //TODO: obtain ZKP for x1, x2, and x2*pinKey
        BigInteger ZKPx1 = BigIntegers.ZERO;
        BigInteger ZKPx2 = BigIntegers.ZERO;
        BigInteger ZKPx2s = BigIntegers.ZERO;
        this.status = ACTOR_STATUS.AS_PASSIVE_PAYLOAD_PREPARED;
        return new jpakePassivePayload(G1,G2,B,ZKPx1,ZKPx2,ZKPx2s);
    }

    public void activeVerifyPassivePayload(jpakePassivePayload ppl)
    {
        //TODO: verification of ZKP sent by passive, if failed, throw an exception
        this.G1_recv = ppl.getG1();
        this.G2_recv = ppl.getG2();
        this.A_recv = ppl.getA();
        this.status = ACTOR_STATUS.AS_PASSIVE_PAYLOAD_VERIFIED;
    }

    public jpakeActiveSecondPayload activeSecondPayload(){
        ECPoint A = G1.add(G1_recv.add(G2_recv)).multiply(x2.multiply(pinKey).mod(n));

        //TODO: get ZKP for x2*pinKey
        BigInteger ZKPx2s = BigIntegers.ZERO;
        this.status = ACTOR_STATUS.AS_ACTIVE_SECOND_PAYLOAD_PREPARED;
        return new jpakeActiveSecondPayload(A, ZKPx2s);
    }

    public void passiveVerifyActiveSecondPayload(jpakeActiveSecondPayload aspl)
    {
        //TODO: verification of ZKP for active second payload, if not ok, throw an exception
        this.A_recv = aspl.getA();
        this.status = ACTOR_STATUS.AS_ACTIVE_SECOND_PAYLOAD_VERIFIED;
    }

    public ECPoint ComputeCommonKey()
    {
        return A_recv.subtract(G2_recv.multiply(x2.multiply(pinKey).mod(n))).multiply(x2);
    }
}
