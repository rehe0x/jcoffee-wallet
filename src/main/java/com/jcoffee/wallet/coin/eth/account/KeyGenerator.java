package com.jcoffee.wallet.coin.eth.account;

import com.jcoffee.wallet.common.Account;
import com.jcoffee.wallet.util.Hash;
import com.jcoffee.wallet.util.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * @program blockchain_study
 * @description:
 * @author: Horng
 * @create: 2020/09/02 16:37
 */
public class KeyGenerator {
    // Base58 encode prefix，不同的prefix可以定制地址的首字母

    static final String PubKeyPrefix = "00";

    static final byte PrivKeyPrefix = -128;

    static final String PrivKeyPrefixStr = "80";

    static final byte PrivKeySuffix = 0x01;

    static int keyGeneratedCount = 1;

    static boolean debug = true;

    static KeyPairGenerator sKeyGen;

    static ECGenParameterSpec sEcSpec;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static boolean ParseArguments(String[] argv) {
        for (int i = 0; i < argv.length - 1; i++) {
            if ("-n".equals(argv[i])) {
                try {
                    keyGeneratedCount = Integer.parseInt(argv[i + 1]);
                    i = i + 1;
                    continue;
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    return false;
                }
            } else if ("-debug".equals(argv[i])) {
                debug = true;
            } else {
                System.out.println(argv[i] + " not supported...");
                return false;
            }
        }
        return keyGeneratedCount > 0;
    }


    public static Account createAddress(){
        Account key = new Account();
        key.Reset();
        KeyGenerator generator = new KeyGenerator();
        generator.GenerateKey(key);
        return key;
    }


    public KeyGenerator() {
        Init();
    }

    private void Init() {
        // Initialize key generator
        // The specific elliptic curve used is the secp256k1.
        try {
            sKeyGen = KeyPairGenerator.getInstance("EC");
            sEcSpec = new ECGenParameterSpec("secp256k1");
            if (sKeyGen == null) {
                System.out.println("Error: no ec algorithm");
                System.exit(-1);
            }
            sKeyGen.initialize(sEcSpec); // 采用secp256K1标准的椭圆曲线加密算法
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

    public boolean GenerateKey(Account key) {
        key.Reset();
        // Generate key pair，依据椭圆曲线算法产生公私钥对
        KeyPair kp = sKeyGen.generateKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();
        ECPrivateKey epvt = (ECPrivateKey) pvt;

        // 私钥16进制字符串
        String sepvt = Utils.AdjustTo64(epvt.getS().toString(16)).toUpperCase();
        if (debug) {
            System.out.println("Privkey[" + sepvt.length() + "]: " + sepvt);
        }
        key.SetPrivKey(sepvt);

        // 获取X，Y坐标点， sx + sy 获取公钥 去掉04
        ECPublicKey epub = (ECPublicKey) pub;
        ECPoint pt = epub.getW();
        String sx = Utils.AdjustTo64(pt.getAffineX().toString(16)).toUpperCase();
        String sy = Utils.AdjustTo64(pt.getAffineY().toString(16)).toUpperCase();
        String bcPub = sx + sy;

        if (debug) {
            System.out.println("Pubkey[" + bcPub.length() + "]: " + bcPub);
        }
        key.SetPubKey(bcPub);

        //公钥（去掉04后剩下64字节）经过Keccak-256单向散列函数变成了32字节，然后取后20字节作为地址 加上0x
        String k = Hash.sha3(bcPub);
        if (debug) {
            System.out.println("sha3: " + k.toLowerCase());
        }
        byte[] p = Utils.HexStringToByteArray(k);
        byte[] checksum = new byte[20];
        System.arraycopy(p, p.length-20, checksum, 0, 20);

        if (debug) {
            System.out.println("address: " + "0x"+Utils.bytesToHexString(checksum).toUpperCase());
        }
        key.SetAddress("0x"+Utils.bytesToHexString(checksum).toUpperCase());
        return true;
    }


}
