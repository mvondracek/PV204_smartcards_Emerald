package jpake;

import java.math.BigInteger;

import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;

public final class jpakePassivePayload {
    private final ECPoint G1;
    private final ECPoint G2;
    private final ECPoint A;
    private final BigInteger ZKPx1;
    private final BigInteger ZKPx2;
    private final BigInteger ZKPx2s;

    public jpakePassivePayload(ECPoint G1, ECPoint G2, ECPoint A, BigInteger ZKPx1, BigInteger ZKPx2, BigInteger ZKPx2s){
        if(G1 == null || G2 == null || A==null || ZKPx1 == null || ZKPx2 == null || ZKPx2s == null){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }
        this.G1 = G1;
        this.G2 = G2;
        this.A = A;
        this.ZKPx1 = ZKPx1;
        this.ZKPx2 = ZKPx2;
        this.ZKPx2s = ZKPx2s;
    }

    public ECPoint getG1() {
        return this.G1;
    }
    public ECPoint getG2() {
        return this.G2;
    }
    public ECPoint getA() {
        return this.A;
    }
    public BigInteger getZKPx1() {
        return this.ZKPx1;
    }
    public BigInteger getZKPx2() {
        return this.ZKPx2;
    }
    public BigInteger getZKPx2s() {
        return this.ZKPx2s;
    }
}
