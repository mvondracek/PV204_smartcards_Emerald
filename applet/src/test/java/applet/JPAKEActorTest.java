package applet;

import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class JPAKEActorTest {
    @Test
    public void exampleTest(){
        byte[] uid = "deadbeef".getBytes();
        byte[] pin_key = new byte[10];
        jpakeactor.JPAKEActor a = new jpakeactor.JPAKEActor(uid, pin_key);
        a.prepareR1Data();
        Assert.assertTrue(true);
    }
}
