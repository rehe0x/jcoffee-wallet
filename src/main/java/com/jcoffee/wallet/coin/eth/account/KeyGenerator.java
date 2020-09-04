package com.jcoffee.wallet.coin.eth.account;

import com.jcoffee.wallet.common.Account;
import com.jcoffee.wallet.util.ECKeyPair;
import com.jcoffee.wallet.util.Hash;
import com.jcoffee.wallet.util.Secp256k1;
import com.jcoffee.wallet.util.Utils;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * @program jcoffee-wallet
 * @description:
 * @author: Horng
 * @create: 2020/09/02 16:37
 */
public class KeyGenerator {
    // Base58 encode prefix，不同的prefix可以定制地址的首字母
    static final String addrPrefix = "0x";

    static boolean debug = true;

    public static Account generateAccount(String privateKey) {
        String priKey = null;
        String pubKey = null;
        if(privateKey == null){
            // Generate key pair，依据椭圆曲线算法产生公私钥对
            KeyPair kp = ECKeyPair.sKeyGen.generateKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey pvt = kp.getPrivate();
            ECPrivateKey epvt = (ECPrivateKey) pvt;
            // 私钥16进制字符串
            priKey = Utils.AdjustTo64(epvt.getS().toString(16)).toUpperCase();

            // 获取X，Y坐标点，“04” + sx + sy即可获得完整的公钥，但是这里我们不要04
            ECPublicKey epub = (ECPublicKey) pub;
            ECPoint pt = epub.getW();
            String sx = Utils.AdjustTo64(pt.getAffineX().toString(16)).toUpperCase();
            String sy = Utils.AdjustTo64(pt.getAffineY().toString(16)).toUpperCase();
            pubKey = sx + sy;
        }else{
            //通过私钥参数获取公钥
            priKey = privateKey;
            byte[] pubByte  = Secp256k1.publicKeyFromPrivate(Utils.HexStringToByteArray(priKey), false);
            //去掉私钥前缀04
            byte[] pb = new byte[pubByte.length - 1];
            System.arraycopy(pubByte, 1, pb, 0, pubByte.length - 1);
            pubKey = Utils.bytesToHexString(pb);
        }

        if (debug) {
            System.out.println("Privkey[" + priKey.length() + "]: " + priKey);
            System.out.println("Pubkey[" + pubKey.length() + "]: " + pubKey);
        }

        //公钥（去掉04后剩下64字节）经过Keccak-256单向散列函数变成了32字节，然后取后20字节作为地址 加上0x
        String s3 = Hash.sha3(pubKey);
        if (debug) {
            System.out.println("sha3: " + s3.toLowerCase());
        }
        byte[] p = Utils.HexStringToByteArray(s3);
        byte[] checksum = new byte[20];
        System.arraycopy(p, p.length-20, checksum, 0, 20);

        String wifAddress = addrPrefix + Utils.bytesToHexString(checksum).toUpperCase();

        if (debug) {
            System.out.println("address: " +wifAddress);
        }

        Account account = new Account(priKey, pubKey, wifAddress);
        return account;
    }



}
