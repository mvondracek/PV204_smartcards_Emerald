package applet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

public class SchnorrZKPTest {
    @Test
    void testVerifyTrue() {
        // init curve
        ECNamedCurveParameterSpec curvespec =
            ECNamedCurveTable.getParameterSpec("curve25519");
        ECPoint G = curvespec.getG();
        BigInteger n = curvespec.getN();
        BigInteger coFactor = curvespec.getH();
        BigInteger x1 = ZKPUtils.generateRandomBigInteger(n);

        //init alice
        byte[] aliceName = {'a', 'l', 'i', 'c', 'e'}; // bob knows that it is alice
        SchnorrZKP alice = new SchnorrZKP(G, n, coFactor, x1, aliceName);

        //bob gets get alice's public keys and ZKP result
        ECPoint aliceV = alice.getPublicV();
        ECPoint aliceA = alice.getPublicA();
        BigInteger aliceResult = alice.getResult();

        // bob computes a challenge with alice's public keys, ZKP result and the public parameters
        BigInteger aliceChallenge = ZKPUtils.computeChallenge(G, aliceV, aliceA, aliceName);

        //bob verifies
        assertTrue(ZKPUtils.verify(aliceA, G, aliceV, coFactor, aliceResult, aliceChallenge));

    }
}
