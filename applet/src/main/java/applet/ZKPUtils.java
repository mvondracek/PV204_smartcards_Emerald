package applet;

import javacard.framework.Util;
import javacard.security.MessageDigest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ZKPUtils {
    /**
     * @return c = H(G || V || A || UserID || OtherInfo)
     */
    public static BigInteger computeChallenge (ECPoint G, ECPoint V, ECPoint A, byte[] userID) {
        byte[] concatKey = concatenatePublic(G, V, A, userID);
        BigInteger output;
        MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
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
                                 encodedA.length + userID.length)];
        short currStart = 0;
        Util.arrayCopyNonAtomic(encodedG, (short) 0, output, currStart, (short) encodedG.length);
        currStart += encodedG.length;
        Util.arrayCopyNonAtomic(encodedV, (short) 0, output, currStart, (short) encodedV.length);
        currStart += encodedV.length;
        Util.arrayCopyNonAtomic(encodedA, (short) 0, output, currStart, (short) encodedA.length);
        currStart += encodedA.length;
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

        if(!isValidPoint(publicA)) {
            return false;
        }

        // check if A is not on point of infinity
        if (Axh.isInfinity()) {
            return false;
        }

        // V == G x [r] + A x [c]
        return publicV.equals(Gxr.add(Axc));
    }

    /**
     * Checks if a point is a valid point on a curve
     * source: https://stackoverflow.com/a/6664005
     * @param point ECPoint to check
     * @return true if point is a valid point on the curve
     */
    private static boolean isValidPoint(ECPoint point) {
        ECCurve curve = point.getCurve();
        BigInteger x = point.getXCoord().toBigInteger();
        BigInteger y = point.getYCoord().toBigInteger();
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();
        BigInteger lhs = y.pow(2);
        // y^2 = x^3 + ax + b
        BigInteger rhs = x.pow(3).add(a.multiply(x)).add(b);

        return lhs.equals(rhs);
    }
}
