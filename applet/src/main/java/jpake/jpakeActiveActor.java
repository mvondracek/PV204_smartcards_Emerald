package jpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public final class jpakeActiveActor extends jpakeActor {
    private ACTIVE_STATUS status;

    private enum ACTIVE_STATUS {
        AS_INIT, AS_FIRST_PAYLOAD_PREPARED,
        AS_INCOMING_VERIFIED, AS_SECOND_PAYLOAD_PREPARED, AS_KEY_DERIVED
    }

    public jpakeActiveActor(byte[] userID, byte[] pinKey) {
        super(userID, pinKey);
        this.status = ACTIVE_STATUS.AS_INIT;
    }

    public jpakeActiveFirstPayload prepareFirstPayload() {
        if(this.status != ACTIVE_STATUS.AS_INIT)
            throw new CryptoException(CryptoException.INVALID_INIT);

        //creating two private keys in range [1, n-1]
        x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        //computing public values to be sent
        G1 = G.multiply(x1);
        G2 = G.multiply(x2);

        //TODO: next we need to calculate ZKP for x1 and x2
        BigInteger ZKPx1 = BigIntegers.ZERO;
        BigInteger ZKPx2 = BigIntegers.ZERO;

        this.status = ACTIVE_STATUS.AS_FIRST_PAYLOAD_PREPARED;
        return new jpakeActiveFirstPayload(G1, G2, ZKPx1, ZKPx2);
    }

    public void activeVerifyPassivePayload(jpakePassivePayload ppl) {
        if(this.status != ACTIVE_STATUS.AS_FIRST_PAYLOAD_PREPARED)
            throw new CryptoException(CryptoException.INVALID_INIT);
        //TODO: verification of ZKP sent by passive, if failed, throw an exception
        this.G1_recv = ppl.getG1();
        this.G2_recv = ppl.getG2();
        this.A_recv = ppl.getA();
        this.status = ACTIVE_STATUS.AS_INCOMING_VERIFIED;
    }

    public jpakeActiveSecondPayload prepareSecondPayload(){
        if(this.status != ACTIVE_STATUS.AS_INCOMING_VERIFIED)
            throw new CryptoException(CryptoException.INVALID_INIT);
        ECPoint A = G1.add(G1_recv.add(G2_recv)).multiply(x2.multiply(pinKey).mod(n));
        //TODO: get ZKP for x2*pinKey
        BigInteger ZKPx2s = BigIntegers.ZERO;
        this.status = ACTIVE_STATUS.AS_SECOND_PAYLOAD_PREPARED;
        return new jpakeActiveSecondPayload(A, ZKPx2s);
    }

    public ECPoint computeCommonKey() {
        if(this.status != ACTIVE_STATUS.AS_SECOND_PAYLOAD_PREPARED)
            throw new CryptoException(CryptoException.INVALID_INIT);
        ECPoint key = super.computeCommonKey();
        this.status = ACTIVE_STATUS.AS_KEY_DERIVED;
        return key;
    }
}
