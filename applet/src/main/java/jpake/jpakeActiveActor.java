package jpake;

import applet.EmIllegalStateException;
import applet.SchnorrZKP;
import applet.ZKPPayload;
import applet.ZKPUtils;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public final class jpakeActiveActor extends jpakeActor {
    private ACTIVE_STATUS status;

    private enum ACTIVE_STATUS {
        AS_INIT, AS_FIRST_PAYLOAD_PREPARED,
        AS_INCOMING_VERIFIED, AS_SECOND_PAYLOAD_PREPARED, AS_KEY_DERIVED
    }

    public jpakeActiveActor(byte[] uid, byte[] pinKey) {
        super(uid, pinKey);
        this.status = ACTIVE_STATUS.AS_INIT;
    }

    public jpakeActiveFirstPayload prepareFirstPayload() {
        if(this.status != ACTIVE_STATUS.AS_INIT) {
            throw new EmIllegalStateException();
        }

        //creating two private keys in range [1, n-1]
        x1 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
        x2 = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

        //computing public values to be sent
        G1 = G.multiply(x1);
        G2 = G.multiply(x2);

        SchnorrZKP szkpx1 = new SchnorrZKP(G, n, coFactor, x1, this.userID);
        ZKPPayload zkpx1 = new ZKPPayload(szkpx1.getPublicA(), szkpx1.getPublicV(),szkpx1.getResult());
        SchnorrZKP szkpx2 = new SchnorrZKP(G, n, coFactor, x2, this.userID);
        ZKPPayload zkpx2 = new ZKPPayload(szkpx2.getPublicA(), szkpx2.getPublicV(),szkpx2.getResult());
        this.status = ACTIVE_STATUS.AS_FIRST_PAYLOAD_PREPARED;
        return new jpakeActiveFirstPayload(this.userID, G1, G2, zkpx1, zkpx2);
    }

    public void verifyIncoming(jpakePassivePayload ppl) throws jpakeKeyAgreementException {
        if(this.status != ACTIVE_STATUS.AS_FIRST_PAYLOAD_PREPARED) {
            throw new EmIllegalStateException();
        }
        ZKPPayload zkp1 = ppl.getZKPx1();
        ZKPPayload zkp2 = ppl.getZKPx2();
        ZKPPayload zkp3 = ppl.getZKPx2s();
        BigInteger challenge1 = ZKPUtils.computeChallenge(G, zkp1.getPublicV(), zkp1.getPublicA(), ppl.getSenderID());
        BigInteger challenge2 = ZKPUtils.computeChallenge(G, zkp2.getPublicV(), zkp2.getPublicA(), ppl.getSenderID());
        BigInteger challenge3 = ZKPUtils.computeChallenge(G, zkp3.getPublicV(), zkp3.getPublicA(), ppl.getSenderID());
        boolean isx1ok = ZKPUtils.verify(zkp1.getPublicA(), G, zkp1.getPublicV(), coFactor, zkp1.getResult(), challenge1);
        boolean isx2ok = ZKPUtils.verify(zkp2.getPublicA(), G, zkp2.getPublicV(), coFactor, zkp2.getResult(), challenge2);
        boolean isx2sok = ZKPUtils.verify(zkp3.getPublicA(), G, zkp3.getPublicV(), coFactor, zkp3.getResult(), challenge3);
        if(!isx1ok || !isx2ok || !isx2sok){
            throw new jpakeKeyAgreementException();
        }
        this.G1_recv = ppl.getG1();
        this.G2_recv = ppl.getG2();
        this.A_recv = ppl.getA();
        this.status = ACTIVE_STATUS.AS_INCOMING_VERIFIED;
    }

    public jpakeActiveSecondPayload prepareSecondPayload(){
        if(this.status != ACTIVE_STATUS.AS_INCOMING_VERIFIED) {
            throw new EmIllegalStateException();
        }
        ECPoint A = G1.add(G1_recv.add(G2_recv)).multiply(x2.multiply(pinKey).mod(n));
        SchnorrZKP szkpx2s = new SchnorrZKP(G, n, coFactor, x2.multiply(pinKey).mod(n), this.userID);
        ZKPPayload zkpx2s = new ZKPPayload(szkpx2s.getPublicA(), szkpx2s.getPublicV(),szkpx2s.getResult());
        this.status = ACTIVE_STATUS.AS_SECOND_PAYLOAD_PREPARED;
        return new jpakeActiveSecondPayload(this.userID, A, zkpx2s);
    }

    public byte[] derivePlainCommonKey() {
        if(this.status != ACTIVE_STATUS.AS_SECOND_PAYLOAD_PREPARED) {
            throw new EmIllegalStateException();
        }
        byte[] key = super.derivePlainCommonKey();
        this.status = ACTIVE_STATUS.AS_KEY_DERIVED;
        return key;
    }
}
