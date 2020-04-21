/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package jpakeR1Msg;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public class jpakeR1Msg {
    private ECPoint G1;
    private ECPoint G2;
    private BigInteger ZKP1;
    private BigInteger ZKP2;
    
    public jpakeR1Msg(ECPoint G1, ECPoint G2, BigInteger ZKP1, BigInteger ZKP2){
        //TODO: add input validation
        this.G1 = G1;
        this.G2 = G2;
        this.ZKP1 = ZKP1;
        this.ZKP2 = ZKP2;
    }
}
