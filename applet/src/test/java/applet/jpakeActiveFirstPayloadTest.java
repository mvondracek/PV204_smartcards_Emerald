package applet;

import java.lang.reflect.Array;
import java.math.BigInteger;

import applet.ZKPPayload;
import javacard.framework.Util;
import javacard.security.CryptoException;
import jpake.jpakeActiveFirstPayload;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;

public class jpakeActiveFirstPayloadTest {

    @Test
    public void serializationTest() throws EmIllegalStateException
    {
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        //TODO: pin-derived key should never be all zero!!!
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        byte[] apdu_payload = afp.toBytes();
        jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(apdu_payload);
        boolean G1same = afp.getG1().equals(restored.getG1());
        boolean G2same = afp.getG2().equals(restored.getG2());
        boolean pubA1same = afp.getZKPx1().getPublicA().equals(restored.getZKPx1().getPublicA());
        boolean pubV1same = afp.getZKPx1().getPublicV().equals(restored.getZKPx1().getPublicV());
        boolean res1same = (afp.getZKPx1().getResult().compareTo(restored.getZKPx1().getResult()) == 0);
        boolean pubA2same = afp.getZKPx2().getPublicA().equals(restored.getZKPx2().getPublicA());
        boolean pubV2same = afp.getZKPx2().getPublicV().equals(restored.getZKPx2().getPublicV());
        boolean res2same = (afp.getZKPx2().getResult().compareTo(restored.getZKPx2().getResult()) == 0);

        if(!G1same || !G2same || !pubA1same || !pubV1same || !res1same || !pubA2same || !pubV2same || !res2same){
            throw new EmIllegalStateException();
        }
    }
}
