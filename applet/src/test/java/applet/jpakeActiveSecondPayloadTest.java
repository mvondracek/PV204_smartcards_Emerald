package applet;

import jpake.jpakeActiveFirstPayload;
import jpake.jpakeActiveSecondPayload;
import jpake.jpakePassiveActor;
import jpake.jpakePassivePayload;
import org.junit.jupiter.api.Test;

public class jpakeActiveSecondPayloadTest {
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
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();

        byte[] apdu_payload = asp.toBytes();
        jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(apdu_payload);
        boolean Asame = asp.getA().equals(restored.getA());
        boolean pubAsame = asp.getZKPx2s().getPublicA().equals(restored.getZKPx2s().getPublicA());
        boolean pubVsame = asp.getZKPx2s().getPublicV().equals(restored.getZKPx2s().getPublicV());
        boolean ressame = (asp.getZKPx2s().getResult().compareTo(restored.getZKPx2s().getResult()) == 0);

        if (!Asame || !pubAsame || !pubVsame || !ressame) {
            throw new EmIllegalStateException();
        }
    }
}
