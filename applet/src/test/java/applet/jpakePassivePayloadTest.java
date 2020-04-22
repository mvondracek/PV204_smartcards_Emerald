package applet;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import javacard.framework.Util;
import jpake.jpakePassiveActor;
import jpake.jpakePassivePayload;
import org.junit.jupiter.api.Test;

public class jpakePassivePayloadTest {

    @Test
    public void serializationOkTest() throws EmIllegalStateException {
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1, 1, 1, 1};
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

    @Test
    public void deserializePayloadBadFormat()
    {
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1, 1, 1, 1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        byte[] apdu_payload = pp.toBytes();

        //let's change the 8th byte - it should contain "65", the length of the encoded EC point
        apdu_payload[8] = 0;
        try {
            jpakePassivePayload restored = jpakePassivePayload.fromBytes(apdu_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadTooShort(){
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1, 1, 1, 1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        byte[] apdu_payload = pp.toBytes();
        // let's cut the payload
        byte[] short_payload = new byte[apdu_payload.length/2];
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,short_payload,(short)0,(short)(apdu_payload.length/2));
        try {
            jpakePassivePayload restored = jpakePassivePayload.fromBytes(short_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(IllegalArgumentException|ArrayIndexOutOfBoundsException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadZeroLength(){
        //what if our payload has length of 0?
        byte[] zero_length_payload = new byte[0];
        try {
            jpakePassivePayload restored = jpakePassivePayload.fromBytes(zero_length_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(ArrayIndexOutOfBoundsException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadNull(){
        //now we pass null to fromBytes
        byte[] null_payload = null;
        try {
            jpakePassivePayload restored = jpakePassivePayload.fromBytes(null);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(NullPointerException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadTooLong(){
        //what if we have something after the end of a "good" payload
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1, 1, 1, 1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        byte[] apdu_payload = pp.toBytes();
        //let's create another array and add something to the end
        byte[] long_payload = new byte[apdu_payload.length*3];
        Util.arrayFillNonAtomic(long_payload,(short)0,(short)(apdu_payload.length*3),(byte)1);
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,long_payload,(short)0,(short)apdu_payload.length);
        try {
            jpakePassivePayload restored = jpakePassivePayload.fromBytes(long_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(EmIllegalArgumentException e) {
            assertTrue(true);
        }
    }
}
