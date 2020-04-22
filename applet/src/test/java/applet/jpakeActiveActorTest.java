package applet;

import org.junit.jupiter.api.Test;

class jpakeActiveActorTest {

    @Test
    public void exampleTest() throws EmIllegalStateException{
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        //TODO: pin-derived key should never be all zero!!!
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload fp = a.prepareFirstPayload();
    }
}
