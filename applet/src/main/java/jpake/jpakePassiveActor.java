package jpake;

import java.math.BigInteger;
import java.security.SecureRandom;

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
        //TODO: obtain ZKP for x1, x2, and x2*pinKey
        BigInteger ZKPx1 = BigIntegers.ZERO;
        BigInteger ZKPx2 = BigIntegers.ZERO;
        BigInteger ZKPx2s = BigIntegers.ZERO;
        this.status = PASSIVE_STATUS.PS_PASSIVE_PAYLOAD_PREPARED;
        return new jpakePassivePayload(G1,G2,B,ZKPx1,ZKPx2,ZKPx2s);
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
