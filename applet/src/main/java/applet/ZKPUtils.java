package applet;

import javacard.framework.Util;
import javacard.security.MessageDigest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

// todo if it is ok to use these
import java.math.BigInteger;
import java.security.SecureRandom;

public class ZKPUtils {
    /**
     * @return c = H(G || V || A || UserID || OtherInfo)
     */
    public static BigInteger computeChallenge (ECPoint G, ECPoint V, ECPoint A, byte[] userID) {
        byte[] concatKey = concatenatePublic(G, V, A, userID);
        BigInteger output;

        // todo select appropriate hash function
        MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA, true);
        byte[] outputBytes = new byte[dig.getLength()];
        dig.doFinal(concatKey, (short) 0, (short) concatKey.length, outputBytes, (short) 0);
        output = new BigInteger(outputBytes);

        return output;
    }

    private static byte[] concatenatePublic(ECPoint G, ECPoint V, ECPoint A, byte[] userID) {
        byte[] encodedG = G.getEncoded(false);
        byte[] encodedV = V.getEncoded(false);
        byte[] encodedA = A.getEncoded(false);
        byte[] output = new byte[(short) (encodedG.length + encodedV.length +
                                 encodedA.length + userID.length + 3)];
        short currStart = 0;
        Util.arrayCopyNonAtomic(encodedG, (short) 0, output, currStart, (short) encodedG.length);
        currStart += encodedG.length + 1;
        Util.arrayCopyNonAtomic(encodedV, (short) 0, output, currStart, (short) encodedV.length);
        currStart += encodedV.length + 1;
        Util.arrayCopyNonAtomic(encodedA, (short) 0, output, currStart, (short) encodedA.length);
        currStart += encodedA.length + 1;
        Util.arrayCopyNonAtomic(userID, (short) 0, output, currStart, (short) userID.length);

        return output;
    }

    /**
     * @param primeOrder        (n in doc) the order of generator
     * @return a private key chosen uniformly at random from [1, n-1]
     */
    public static BigInteger generateRandomBigInteger(BigInteger primeOrder) {
        return BigIntegers.createRandomInRange(BigInteger.ONE,
            primeOrder.subtract(BigInteger.ONE),
            new SecureRandom());
    }

    /**
     * Used by Bob to verify the ZKP with the public information he has available.
     * @param publicA   (A in doc) Alice's public key A = G x [a]
     * @param generator (G in doc) a base point on the curve that serves as a generator
     * @param publicV   (V in doc) a public key, V = G x [v]
     * @param coFactor  (h in doc) the coFactor of the subgroup, usually a small integer up to 4
     * @param result    (r in doc) r = v – (a * c) mod n
     * @param challenge (c in doc), c = H(G || V || A || UserID || OtherInfo)
     * @return A is a valid point on the curve && A x [h] is not at the point of infinity
     * && V == G x [r] + A x [c]
     */
    public static boolean verify(ECPoint publicA, ECPoint generator, ECPoint publicV,
                          BigInteger coFactor, BigInteger result, BigInteger challenge) {
        ECPoint Axh = publicA.multiply(coFactor);
        ECPoint Gxr = generator.multiply(result);
        ECPoint Axc = publicA.multiply(challenge);

        // check if A is a valid point on the curve
        // source: https://stackoverflow.com/a/6664005
        ECCurve curveOfA = publicA.getCurve();
        ECFieldElement xOfPublicA = publicA.getXCoord();
        ECFieldElement yOfPublicA = publicA.getYCoord();
        ECFieldElement a = curveOfA.getA();
        ECFieldElement b = curveOfA.getB();
        ECFieldElement lhs = yOfPublicA.multiply(xOfPublicA);
        ECFieldElement rhs = xOfPublicA.multiply(xOfPublicA)
            .multiply(xOfPublicA).add(a.multiply(xOfPublicA)).add(b);
        if(!lhs.equals(rhs)) return false;

        // check if A is not on point of infinity
        if (Axh.isInfinity()) return false;

        // V == G x [r] + A x [c]
        return publicV == Gxr.add(Axc);
    }
}
