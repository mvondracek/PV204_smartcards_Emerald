package jpake;

import java.math.BigInteger;

import applet.ZKPPayload;
import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.test.FixedSecureRandom;

public final class jpakeActiveSecondPayload {
    private final byte[] senderID;
    private final ECPoint A;
    private final ZKPPayload ZKPx2s;

    public jpakeActiveSecondPayload(byte[] id, ECPoint A, ZKPPayload ZKPx2s){
        if(A == null || ZKPx2s == null){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.senderID = id;
        this.A = A;
        this.ZKPx2s = ZKPx2s;
    }

    public byte[] getSenderID() {
        return this.senderID;
    }

    public ECPoint getA() {
        return this.A;
    }
    public ZKPPayload getZKPx2s() {
        return this.ZKPx2s;
    }
}
