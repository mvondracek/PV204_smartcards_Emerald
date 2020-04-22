package applet;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SchnorrZKP {

    // r = v – (a * c) mod n
    private BigInteger result;

    // (A in doc) Alice's public key A = G x [a]
    private ECPoint publicA;

    // (V in doc) a public key, V = G x [v]
    private ECPoint publicV;

    /**
     *
     * @param generator         (G in doc) a base point on the curve that serves as a generator
     * @param primeOrder        (n in doc) the order of generator
     * @param privateRandomKey  (a in doc) the private key chosen uniformly at random from [1, n-1]
     * @param userID            (UserID in doc) User ID used for challenge
     */
    public SchnorrZKP(ECPoint generator,
                      BigInteger primeOrder,
                      BigInteger privateRandomKey,
                      byte[] userID) {

        // In the setup of the scheme, Alice publishes her public key A = G x [a], where
        // a is the private key chosen uniformly at random from [1, n-1] (step of J-PAKE)
        this.publicA = generator.multiply(privateRandomKey);

        // Alice chooses a number v uniformly at random from [1, n – 1] and computes V = G x [v]
        BigInteger randomV = ZKPUtils.generateRandomBigInteger(primeOrder);
        this.publicV = generator.multiply(randomV);

        // The challenge c = H(G || V || A || UserID || OtherInfo)
        BigInteger challenge = ZKPUtils.computeChallenge(generator, publicV, publicA, userID);

        // Alice computes r = v – (a * c) mod n (and sends it to Bob)
        this.result = computeResult(randomV, privateRandomKey, challenge, primeOrder);
    }

    /**
     * @param randomV           (v in doc) number chosen uniformly at random from [1, n – 1]
     * @param privateRandomKey  (a in doc) the private key chosen uniformly at random from [1, n-1]
     * @param challenge         (c in doc), c = H(G || V || A || UserID || OtherInfo)
     * @param primeOrder        (n in doc) the order of generator
     * @return r = v – (a * c) mod n
     */
    private BigInteger computeResult(BigInteger randomV, BigInteger privateRandomKey,
                                     BigInteger challenge, BigInteger primeOrder) {
        return randomV.subtract((privateRandomKey.multiply(challenge).mod(primeOrder)));
    }

    public BigInteger getResult() {
        return result;
    }

    public ECPoint getPublicA() {
        return publicA;
    }

    public ECPoint getPublicV() {
        return publicV;
    }
}
