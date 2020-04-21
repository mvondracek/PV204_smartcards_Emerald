package jpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.test.FixedSecureRandom;

public class jpakeActiveSecondPayload {

    private ECPoint A;
    private BigInteger ZKPx2s;

    public jpakeActiveSecondPayload(ECPoint A, BigInteger ZKPx2s){
        this.A = A;
        this.ZKPx2s = ZKPx2s;
    }

    public ECPoint getA() { return this.A; }
    public BigInteger getZKPx2s() { return this.ZKPx2s; }
}
