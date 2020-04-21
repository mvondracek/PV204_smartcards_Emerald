package applet;

import jpake.jpakeActor;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class jpakeActorTest {
    @Test
    public void exampleTest(){
        byte[] uid = "deadbeef".getBytes();
        byte[] pin_key = new byte[10];
        jpake.jpakeActor a = new jpake.jpakeActor(uid, jpakeActor.ACTOR_ROLE.AR_ACTIVE, pin_key);
        a.activeFirstPayload();
        Assert.assertTrue(true);
    }
}
