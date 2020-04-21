package applet;

import com.sun.source.tree.AssertTree;
import javacard.security.CryptoException;
import jpake.*;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class jpakeProtocolTest {
    @Test
    public void ifObtainedKeyIsTheSame() throws CryptoException{
        byte[] auid = "Alice".getBytes();
        byte[] buid = "Bob".getBytes();
        byte[] pin_key = new byte[10]; //pin is 0(x10) now
        jpake.jpakeActiveActor a = new jpake.jpakeActiveActor(auid, pin_key);
        jpake.jpakePassiveActor b = new jpakePassiveActor(buid, pin_key);
        jpakeActiveFirstPayload afp = a.prepareFirstPayload();
        b.verifyFirstIncoming(afp);
        jpakePassivePayload pp = b.preparePassivePayload();
        a.verifyIncoming(pp);
        jpakeActiveSecondPayload asp = a.prepareSecondPayload();
        b.verifySecondIncoming(asp);
        ECPoint ckey_a = a.computeCommonKey();
        ECPoint ckey_b = b.computeCommonKey();
        if(!ckey_a.equals(ckey_b)) throw new CryptoException(CryptoException.ILLEGAL_VALUE);
    }
}
