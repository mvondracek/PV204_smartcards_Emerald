package applet;

import javacard.framework.SystemException;
import javacard.framework.Util;
import jpake.jpakeActiveFirstPayload;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class jpakeActiveFirstPayloadTest {

    @Test
    public void serializationOkTest() throws EmIllegalArgumentException, IllegalArgumentException, ArrayIndexOutOfBoundsException, NullPointerException, SystemException
    {
        //test of serialization/deserialization for the "best" case
        //restored and original objects must match
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
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

    @Test
    public void deserializePayloadBadFormat()
    {
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        byte[] apdu_payload = afp.toBytes();
        //let's change the 8th byte - it should contain "65", the length of the encoded EC point
        apdu_payload[8] = 0;
        try {
            jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(apdu_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadTooShort(){
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        byte[] apdu_payload = afp.toBytes();
        // let's cut the payload
        byte[] short_payload = new byte[apdu_payload.length/2];
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,short_payload,(short)0,(short)(apdu_payload.length/2));
        try {
            jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(short_payload);
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
            jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(zero_length_payload);
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
            jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(null);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(NullPointerException e) {
            assertTrue(true);
        }
    }

    @Test
    public void deserializePayloadTooLong(){
        //what if we have something after the end of a "good" payload
        byte[] uid = "ACTIVE".getBytes();
        byte[] pin_key = {1,1,1,1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(uid, pin_key);
        jpake.jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        byte[] apdu_payload = afp.toBytes();
        //let's create another array and add something to the end
        byte[] long_payload = new byte[apdu_payload.length*3];
        Util.arrayFillNonAtomic(long_payload,(short)0,(short)(apdu_payload.length*3),(byte)1);
        Util.arrayCopyNonAtomic(apdu_payload,(short)0,long_payload,(short)0,(short)apdu_payload.length);
        try {
            jpakeActiveFirstPayload restored = jpakeActiveFirstPayload.fromBytes(long_payload);
            fail( "fromBytes didn't thrown an exception");
        }
        catch(EmIllegalArgumentException e) {
            assertTrue(true);
        }
    }
}
