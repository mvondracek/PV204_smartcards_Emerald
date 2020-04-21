package applet;

import jpake.jpakeActiveActor;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class jpakeActiveActorTest {

    @Test
    public void exampleTest() throws Exception{
        byte[] uid = "deadbeef".getBytes();
        byte[] pin_key = new byte[10]; //pin is 0(x10) now
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload fp = a.prepareFirstPayload();
    }
}
