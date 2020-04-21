/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public class jpakeActiveFirstPayload {
    private ECPoint G1;
    private ECPoint G2;
    private BigInteger ZKPx1;
    private BigInteger ZKPx2;

    public jpakeActiveFirstPayload(ECPoint G1, ECPoint G2, BigInteger ZKPx1, BigInteger ZKPx2){
        //TODO: add input validation
        this.G1 = G1;
        this.G2 = G2;
        this.ZKPx1 = ZKPx1;
        this.ZKPx2 = ZKPx2;
    }

    public ECPoint getG1() { return this.G1;}
    public ECPoint getG2() { return this.G2;}
    public BigInteger getZKPx1() { return this.ZKPx1; }
    public BigInteger getZKPx2() { return this.ZKPx2; }
}
