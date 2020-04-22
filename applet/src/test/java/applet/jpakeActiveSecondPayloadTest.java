package applet;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import javacard.framework.Util;

import jpake.jpakeActiveSecondPayload;
import jpake.jpakePassiveActor;
import jpake.jpakePassivePayload;

import org.junit.jupiter.api.Test;

public class jpakeActiveSecondPayloadTest {
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
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        byte[] apdu_payload = asp.toBytes();
        //let's change the 8th byte - it should contain "65", the length of the encoded EC point
        apdu_payload[8] = 0;
        try {
            jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(apdu_payload);
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
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        byte[] apdu_payload = asp.toBytes();
        // let's cut the payload
        byte[] short_payload = new byte[apdu_payload.length/2];
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,short_payload,(short)0,(short)(apdu_payload.length/2));
        try {
            jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(short_payload);
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
            jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(zero_length_payload);
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
            jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(null);
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
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        byte[] apdu_payload = asp.toBytes();
        //let's create another array and add something to the end
        byte[] long_payload = new byte[apdu_payload.length*3];
        Util.arrayFillNonAtomic(long_payload,(short)0,(short)(apdu_payload.length*3),(byte)1);
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,long_payload,(short)0,(short)apdu_payload.length);
        try {
            jpakeActiveSecondPayload restored = jpakeActiveSecondPayload.fromBytes(long_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(EmIllegalArgumentException e) {
            assertTrue(true);
        }
    }
}
