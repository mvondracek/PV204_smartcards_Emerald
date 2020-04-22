package applet;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public final class ZKPPayload {
    private final ECPoint publicA;
    private final ECPoint publicV;
    private final BigInteger result;

    public ZKPPayload(ECPoint A, ECPoint V, BigInteger result){
        this.publicA = A;
        this.publicV = V;
        this.result = result;
    }

    public ECPoint getPublicA() {
        return publicA;
    }

    public ECPoint getPublicV() {
        return publicV;
    }

    public BigInteger getResult() {
        return result;
    }
}
