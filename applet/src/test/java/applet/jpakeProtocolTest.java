package applet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import java.util.Arrays;
import javacard.framework.Util;
import jpake.jpakeActiveFirstPayload;
import jpake.jpakeActiveSecondPayload;
import jpake.jpakeKeyAgreementException;
import jpake.jpakePassiveActor;
import jpake.jpakePassivePayload;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

class jpakeProtocolTest {
    @Test
    public void ifObtainedKeyIsTheSame() throws jpakeKeyAgreementException {
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1,1,1,1};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        b.verifySecondIncoming(asp);
        byte[] pckey_a = a.derivePlainCommonKey();
        byte[] pckey_b = b.derivePlainCommonKey();
        if(Util.arrayCompare(pckey_a, (short)0, pckey_b, (short)0, (short)pckey_a.length) !=0) throw new EmIllegalStateException();
    }

    @Test
    public void protocolSerializeDeserialize() throws jpakeKeyAgreementException {
        final byte[] pin_key = {1, 1, 1, 1};
        //TODO: pin-derived key should never be all zero!!!
        jpake.jpakeActiveActor computer = new jpake.jpakeActiveActor("COMPUTER".getBytes(), pin_key);
        jpake.jpakePassiveActor card = new jpakePassiveActor("CARD".getBytes(), pin_key);

        final byte[] afpBytes = computer.prepareFirstPayload().toBytes();
        // computer --> afpBytes --> card
        card.verifyFirstIncoming(jpakeActiveFirstPayload.fromBytes(afpBytes));
        final byte[] ppBytes = card.preparePassivePayload().toBytes();
        // computer <-- ppBytes <-- card
        computer.verifyIncoming(jpakePassivePayload.fromBytes(ppBytes));
        final byte[] aspBytes = computer.prepareSecondPayload().toBytes();
        // computer --> aspBytes --> card
        card.verifySecondIncoming(jpakeActiveSecondPayload.fromBytes(aspBytes));

        final byte[] pckey_a = computer.derivePlainCommonKey();
        final byte[] pckey_b = card.derivePlainCommonKey();

        Assert.assertArrayEquals(pckey_a, pckey_b);
    }

    @Test
    public void testResetSession() throws jpakeKeyAgreementException {
        byte[] auid = "Alice".getBytes();   //active
        byte[] buid = "Bob".getBytes();     //passive
        byte[] cuid = "Charlie".getBytes();   //active
        byte[] duid = "Dave".getBytes();     //passive
        //two actors are created with the same PIN
        byte[] pin_key = {1,1,1,1};
        byte[] pin_key2 = {2,2,2,2};
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        jpake.jpakeActiveActor c = new jpake.jpakeActiveActor(cuid, pin_key2);
        jpake.jpakePassiveActor d = new jpake.jpakePassiveActor(duid, pin_key2);
        jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        b.verifySecondIncoming(asp);
        byte[] pckey_ab = a.derivePlainCommonKey();
        byte[] pckey_ba = b.derivePlainCommonKey();
        Assert.assertArrayEquals(pckey_ab, pckey_ba);

        //reset first pair of actors
        a.clearSessionData();
        b.clearSessionData();
        //active1 and passive2 are tested, PINs are different
        afp = a.prepareFirstPayload();
        d.verifyFirstIncoming(afp);
        pp = d.preparePassivePayload();
        a.verifyIncoming(pp);
        asp = a.prepareSecondPayload();
        d.verifySecondIncoming(asp);
        byte[] pckey_ad = a.derivePlainCommonKey();
        byte[] pckey_da = d.derivePlainCommonKey();
        //keys should be different
        assertFalse(Arrays.equals(pckey_ad, pckey_da));

        a.clearSessionData();
        d.clearSessionData();
        //active2 and passive1 test, PINs are different
        afp = c.prepareFirstPayload();
        b.verifyFirstIncoming(afp);
        pp = b.preparePassivePayload();
        c.verifyIncoming(pp);
        asp = c.prepareSecondPayload();
        b.verifySecondIncoming(asp);
        byte[] pckey_cb = c.derivePlainCommonKey();
        byte[] pckey_bc = b.derivePlainCommonKey();
        //keys should be different
        assertFalse(Arrays.equals(pckey_cb, pckey_bc));

        c.clearSessionData();
        b.clearSessionData();
        //establishing connection between Alice and Bob again, PINs are the same
        afp = a.prepareFirstPayload();
        b.verifyFirstIncoming(afp);
        pp = b.preparePassivePayload();
        a.verifyIncoming(pp);
        asp = a.prepareSecondPayload();
        b.verifySecondIncoming(asp);
        byte[] pckey_ab2 = a.derivePlainCommonKey();
        byte[] pckey_ba2 = b.derivePlainCommonKey();
        //these keys must be identical
        Assert.assertArrayEquals(pckey_ab2, pckey_ba2);
        //but they must be different from the Alice-Bob first key
        assertFalse(Arrays.equals(pckey_ab2, pckey_ab));
    }
}
