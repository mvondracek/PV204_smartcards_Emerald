package applet;

import jpake.jpakeActiveActor;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class jpakeActiveActorTest {

    @Test
    public void exampleTest() throws EmIllegalStateException{
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload fp = a.prepareFirstPayload();
    }
}
