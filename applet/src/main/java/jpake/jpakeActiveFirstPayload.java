/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpake;

import java.math.BigInteger;
import javacard.security.CryptoException;
import org.bouncycastle.math.ec.ECPoint;

public final class jpakeActiveFirstPayload {
    private final ECPoint G1;
    private final ECPoint G2;
    private final BigInteger ZKPx1;
    private final BigInteger ZKPx2;

    public jpakeActiveFirstPayload(ECPoint G1, ECPoint G2, BigInteger ZKPx1, BigInteger ZKPx2){
        if(G1 == null || G2 == null || ZKPx1 == null || ZKPx2 == null){
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }

        this.G1 = G1;
        this.G2 = G2;
        this.ZKPx1 = ZKPx1;
        this.ZKPx2 = ZKPx2;
    }

    public ECPoint getG1() {
        return this.G1;
    }
    public ECPoint getG2() {
        return this.G2;
    }
    public BigInteger getZKPx1() {
        return this.ZKPx1;
    }
    public BigInteger getZKPx2() {
        return this.ZKPx2;
    }
}
