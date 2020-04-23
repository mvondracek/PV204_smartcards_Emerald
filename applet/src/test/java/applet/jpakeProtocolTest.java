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
    public void ifObtainedKeyIsTheSame() throws jpakeKeyAgreementException {
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

    @Test
    public void protocolSerializeDeserialize() throws jpakeKeyAgreementException {
        final byte[] pin_key = {1,1,1,1};
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
}
