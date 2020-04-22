package jpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import applet.SchnorrZKP;
import applet.ZKPPayload;
import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public final class jpakePassiveActor extends jpakeActor{
    private PASSIVE_STATUS status;

    private enum PASSIVE_STATUS {PS_INIT, PS_FIRST_INCOMING_VERIFIED, PS_PASSIVE_PAYLOAD_PREPARED,
                              PS_SECOND_INCOMING_VERIFIED, PS_KEY_DERIVED
    }

    public jpakePassiveActor(byte[] userID, byte[] pinKey){
        super(userID, pinKey);
        this.status = PASSIVE_STATUS.PS_INIT;
    }

    public void verifyFirstIncoming(jpakeActiveFirstPayload afpl)
    {
        if(this.status != PASSIVE_STATUS.PS_INIT)
            throw new CryptoException(CryptoException.INVALID_INIT);
        //TODO: passive verifies ZKP from active's first msg, if no, then throw exception
        this.G1_recv = afpl.getG1();
        this.G2_recv = afpl.getG2();
        this.status = PASSIVE_STATUS.PS_FIRST_INCOMING_VERIFIED;
    }

    public jpakePassivePayload preparePassivePayload()
    {
        if(this.status != PASSIVE_STATUS.PS_FIRST_INCOMING_VERIFIED)
            throw new CryptoException(CryptoException.INVALID_INIT);

        this.x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        this.x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        this.G1 = G.multiply(x1);
        this.G2 = G.multiply(x2);

        ECPoint B = G1_recv.add(G2_recv.add(G1)).multiply(x2.multiply(pinKey).mod(n));
        SchnorrZKP szkpx1 = new SchnorrZKP(G, n, coFactor, x1, this.userID);
        ZKPPayload zkpx1 = new ZKPPayload(szkpx1.getPublicA(), szkpx1.getPublicV(),szkpx1.getResult());
        SchnorrZKP szkpx2 = new SchnorrZKP(G, n, coFactor, x2, this.userID);
        ZKPPayload zkpx2 = new ZKPPayload(szkpx2.getPublicA(), szkpx2.getPublicV(),szkpx2.getResult());
        SchnorrZKP szkpx2s = new SchnorrZKP(G, n, coFactor, x2.multiply(pinKey).mod(n), this.userID);
        ZKPPayload zkpx2s = new ZKPPayload(szkpx2s.getPublicA(), szkpx2s.getPublicV(),szkpx2s.getResult());

        this.status = PASSIVE_STATUS.PS_PASSIVE_PAYLOAD_PREPARED;
        return new jpakePassivePayload(this.userID, G1,G2,B,zkpx1,zkpx2,zkpx2s);
    }

    public void verifySecondIncoming(jpakeActiveSecondPayload aspl)
    {
        if(this.status != PASSIVE_STATUS.PS_PASSIVE_PAYLOAD_PREPARED)
            throw new CryptoException(CryptoException.INVALID_INIT);

        //TODO: verification of ZKP for active second payload, if not ok, throw an exception
        this.A_recv = aspl.getA();
        this.status = PASSIVE_STATUS.PS_SECOND_INCOMING_VERIFIED;
    }

    public ECPoint computeCommonKey()
    {
        if(this.status != PASSIVE_STATUS.PS_SECOND_INCOMING_VERIFIED)
            throw new CryptoException(CryptoException.INVALID_INIT);

        ECPoint key = super.computeCommonKey();
        this.status = PASSIVE_STATUS.PS_KEY_DERIVED;
        return key;
    }
}
