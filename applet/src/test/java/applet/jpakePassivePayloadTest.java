package applet;

import jpake.jpakeActiveSecondPayload;
import jpake.jpakePassiveActor;
import jpake.jpakePassivePayload;
import org.junit.jupiter.api.Test;

public class jpakePassivePayloadTest {

    @Test
    public void serializationTest() throws EmIllegalStateException {
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1, 1, 1, 1};
        //TODO: pin-derived key should never be all zero!!!
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();

        byte[] apdu_payload = pp.toBytes();
        jpakePassivePayload restored = jpakePassivePayload.fromBytes(apdu_payload);
        boolean G1same = pp.getG1().equals(restored.getG1());
        boolean G2same = pp.getG2().equals(restored.getG2());
        boolean Asame = pp.getA().equals(restored.getA());
        boolean publicA1same = pp.getZKPx1().getPublicA().equals(restored.getZKPx1().getPublicA());
        boolean publicV1same = pp.getZKPx1().getPublicV().equals(restored.getZKPx1().getPublicV());
        boolean publicR1same = (pp.getZKPx1().getResult().compareTo(restored.getZKPx1().getResult()) == 0);
        boolean publicA2same = pp.getZKPx2().getPublicA().equals(restored.getZKPx2().getPublicA());
        boolean publicV2same = pp.getZKPx2().getPublicV().equals(restored.getZKPx2().getPublicV());
        boolean publicR2same = (pp.getZKPx2().getResult().compareTo(restored.getZKPx2().getResult()) == 0);
        boolean publicA3same = pp.getZKPx2s().getPublicA().equals(restored.getZKPx2s().getPublicA());
        boolean publicV3same = pp.getZKPx2s().getPublicV().equals(restored.getZKPx2s().getPublicV());
        boolean publicR3same = (pp.getZKPx2s().getResult().compareTo(restored.getZKPx2s().getResult()) == 0);

        if (!G1same || !G2same || !Asame || !publicA1same || !publicA2same || !publicA3same || !publicV1same || !publicV2same || !publicV3same || !publicR1same || !publicR2same || !publicR3same) {
            throw new EmIllegalStateException();
        }
    }
}
