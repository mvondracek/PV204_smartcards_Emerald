package jpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public class jpakePassivePayload {
    private ECPoint G1;
    private ECPoint G2;
    private ECPoint A;
    private BigInteger ZKPx1;
    private BigInteger ZKPx2;
    private BigInteger ZKPx2s;

    public jpakePassivePayload(ECPoint G1, ECPoint G2, ECPoint A, BigInteger ZKPx1, BigInteger ZKPx2, BigInteger ZKPx2s){
        this.G1 = G1;
        this.G2 = G2;
        this.A = A;
        this.ZKPx1 = ZKPx1;
        this.ZKPx2 = ZKPx2;
        this.ZKPx2s = ZKPx2s;
    }

    public ECPoint getG1() { return this.G1;}
    public ECPoint getG2() { return this.G2;}
    public ECPoint getA() { return this.A;}
    public BigInteger getZKPx1() { return this.ZKPx1; }
    public BigInteger getZKPx2() { return this.ZKPx2; }
    public BigInteger getZKPx2s() { return this.ZKPx2s; }
}
