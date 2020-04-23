package applet;

import javacard.framework.Util;
import javacard.security.CryptoException;
import jpake.*;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class jpakeProtocolTest {
    @Test
    public void ifObtainedKeyIsTheSame() throws EmIllegalStateException{
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
    public void testResetSession(){
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
        if(Util.arrayCompare(pckey_ab, (short)0, pckey_ba, (short)0, (short)pckey_ab.length) !=0) throw new EmIllegalStateException();
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
        byte[] pckey_da = b.derivePlainCommonKey();
        //keys should be different
        if(Util.arrayCompare(pckey_ad, (short)0, pckey_da, (short)0, (short)pckey_ad.length) == 0) throw new EmIllegalStateException();
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
        if(Util.arrayCompare(pckey_cb, (short)0, pckey_bc, (short)0, (short)pckey_cb.length) == 0) throw new EmIllegalStateException();
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
        if(Util.arrayCompare(pckey_ab2, (short)0, pckey_ba2, (short)0, (short)pckey_ab2.length) !=0) throw new EmIllegalStateException();
        //but they must be different from the Alice-Bob first key
        if(Util.arrayCompare(pckey_ab2, (short)0, pckey_ab, (short)0, (short)pckey_ab2.length) ==0) throw new EmIllegalStateException();
    }
}
