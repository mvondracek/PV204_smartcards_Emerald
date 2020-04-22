package applet;

import javacard.framework.Util;

import jpake.*;

import org.junit.jupiter.api.Test;

class jpakeProtocolTest {
    @Test
    public void ifObtainedKeyIsTheSame() throws EmIllegalStateException{
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = {1,1,1,1};
        //TODO: pin-derived key should never be all zero!!!
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
}
