package com.jcoffee.wallet.util;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointUtil;

import java.math.BigInteger;

/**
 * @program jcoffee-wallet 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/04 13:37 
 */
public class Secp256k1 {

    private static final ECDomainParameters CURVE;
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    static {
        FixedPointUtil.precompute(CURVE_PARAMS.getG());
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
    }

    public static byte[] publicKeyFromPrivate(byte[] privKeyBytes, boolean compressed) {
        BigInteger privKey = new BigInteger(1, privKeyBytes);
        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }
        ECPoint multiply = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        byte[] publicKey = multiply.getEncoded(compressed);
        return publicKey;
    }
}
