package com.jcoffee.wallet.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * @program jcoffee-wallet 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/04 14:22 
 */
public class ECKeyPair {
    public static KeyPairGenerator sKeyGen;

    public static ECGenParameterSpec sEcSpec;

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            sKeyGen = KeyPairGenerator.getInstance("EC");
            sEcSpec = new ECGenParameterSpec("secp256k1");
            // 采用secp256K1标准的椭圆曲线加密算法
            sKeyGen.initialize(sEcSpec);
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Error:" + e);
            System.exit(-1);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error:" + e);
            System.exit(-1);
        } catch (Exception e) {
            System.out.println("Error:" + e);
            System.exit(-1);
        }
    }

}
