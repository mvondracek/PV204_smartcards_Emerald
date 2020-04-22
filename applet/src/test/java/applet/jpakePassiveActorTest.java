package applet;

import jpake.jpakePassiveActor;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;


public class jpakePassiveActorTest {

    @Test
    public void wrongStatusBeforePreparingPayload() {

        byte[] uid = "PASSIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        //TODO: pin-derived key should never be all zero!!!
        jpake.jpakePassiveActor p = new jpake.jpakePassiveActor(uid, pin_key);
        try {
            p.preparePassivePayload();  //that should fail, since we have wrong status
            fail( "preparePassivePayload didn't thrown an exception");
        }
        catch (EmIllegalStateException ce){
            assertTrue(true);
        }

    }
}
