package applet;

import javacard.security.CryptoException;
import jpake.jpakePassiveActor;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;


public class jpakePassiveActorTest {

    @Test
    public void wrongStatusBeforePreparingPayload() {

        byte[] uid = "deadbeef".getBytes();
        byte[] pin_key = new byte[10]; //pin is 0(x10) now
        jpake.jpakePassiveActor p = new jpake.jpakePassiveActor(uid, pin_key);
        try {
            p.preparePassivePayload();  //that should fail, since we have wrong status
            fail( "preparePassivePayload didn't thrown an exception");
        }
        catch (CryptoException ce){

        }

    }
}
