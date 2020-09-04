package com.jcoffee.wallet.coin.btc.account;

import com.jcoffee.wallet.common.Account;
import com.jcoffee.wallet.util.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * @program jcoffee-wallet
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

    public static void main(String args[]) {
        if (args.length > 1) {
            if (!ParseArguments(args)) {
                System.out.println("Arguments error, please check...");
                System.exit(-1);
            }
        }

        Account key = new Account();
        key.Reset();
        KeyGenerator generator = new KeyGenerator();

        for (int i = 0; i < keyGeneratedCount; i++) {
            key.Reset();
            if (generator.GenerateKey(key)) {
                System.out.println(key.ToString());
            } else {
                System.out.println("Generate key error...");
                System.exit(-1);
            }
        }
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

        // 获取X，Y坐标点，“04” + sx + sy即可获得完整的公钥，但是这里我们需要压缩的公钥
        ECPublicKey epub = (ECPublicKey) pub;
        ECPoint pt = epub.getW();
        String sx = Utils.AdjustTo64(pt.getAffineX().toString(16)).toUpperCase();
        String sy = Utils.AdjustTo64(pt.getAffineY().toString(16)).toUpperCase();
        String bcPub = "04" + sx + sy;

        if (debug) {
            System.out.println("Pubkey[" + bcPub.length() + "]: " + bcPub);
        }

        // Here we get compressed pubkey
        // 获取压缩公钥的方法：Y坐标最后一个字节是偶数，则 "02" + sx，否则 "03" + sx
        byte[] by = Utils.HexStringToByteArray(sy);
        byte lastByte = by[by.length - 1];

        String compressedPk;
        if ((int) (lastByte) % 2 == 0) {
            compressedPk = "02" + sx;
        } else {
            compressedPk = "03" + sx;
        }

        if (debug) {
            System.out.println("compressed pubkey: " + compressedPk);
        }
        key.SetPubKey(compressedPk);

        // We now need to perform a SHA-256 digest on the public key,
        // followed by a RIPEMD-160 digest.
            // 对压缩的公钥做SHA256摘要
        byte[] s1 = Utils.sha256(Utils.HexStringToByteArray(compressedPk));

        if (debug) {
            System.out.println("sha: " + Utils.bytesToHexString(s1).toUpperCase());
        }

        // We use the Bouncy Castle provider for performing the RIPEMD-160 digest
        // since JCE does not implement this algorithm.
        // SHA256摘要之后做RIPEMD-160，这里调用Bouncy Castle的库，不知道的同学百度搜一下就懂了
        s1 = Utils.ripemd160(s1);
        if (debug) {
            System.out.println("rmd: " + Utils.bytesToHexString(s1).toUpperCase());
        }

        // 添加NetworkID 00
        byte[] networkID = new BigInteger(PubKeyPrefix, 16).toByteArray();
        s1 = Utils.add(networkID, s1);
        if (debug) {
            System.out.println("net: " + Utils.bytesToHexString(s1).toUpperCase());
        }

        //两次sha
        byte[] sha2 = Utils.sha256(Utils.sha256(s1));
        if (debug) {
            System.out.println("sha2: " + Utils.bytesToHexString(sha2).toUpperCase());
        }

        //截取sha2结果 前4个字节 添加到s1
        byte[] checksum = new byte[4];
        System.arraycopy(sha2, 0, checksum, 0, 4);
        byte[] s2 = Utils.add(s1, checksum);
        if (debug) {
            System.out.println("before base58: " + Utils.bytesToHexString(s2).toUpperCase());
        }
        // 到此，可以获取WIF格式的地址
        key.SetAddress(Base58.encode(s2));
        if (debug) {
            System.out.println("addr: " + Base58.encode(s2));
        }

        // Lastly, we get compressed privkey 最后获取压缩的私钥
        byte[] pkBytes = Utils.HexStringToByteArray("80" + sepvt + "01");
        if (debug) {
            System.out.println("raw compressed privkey: " + Utils.bytesToHexString(pkBytes).toUpperCase());
        }

        //两次SHA256加密压缩私钥
        byte[] shasecond = Utils.sha256(Utils.sha256(pkBytes));

        //取sha2结果的前4字节(c47e83ff)，加到第1步结果的末尾
        byte[] pf = new byte[4];
        System.arraycopy(shasecond, 0, pf, 0, 4);
        byte[] p2 = Utils.add(pkBytes, pf);

        key.SetPrivKey(Base58.encode(p2));
        if (debug) {
            System.out.println("compressed private key: " + Base58.encode(p2));
        }

        if (debug) {
            System.out.println("original private key: " + WIFPrivkey2Privkey(Base58.encode(p2)).toUpperCase());
        }


        return true;
    }

    public static String WIFPrivkey2Privkey(String wifPrivKey){
        if (wifPrivKey == null || "".equals(wifPrivKey)) {
            System.out.println("Invalid WIF private key");
        }
        byte[] base58Decode = Base58.decode(wifPrivKey);
        String decodeStr = Utils.bytesToHexString(base58Decode);
        if (decodeStr.length() != 76) {
            System.out.println("Invalid WIF private key");
        }

        String version = decodeStr.substring(0, 2);
        String suffix = decodeStr.substring(66, 68);
        if (!"80".equals(version) || !"01".equals(suffix)) {
            System.out.println("Invalid WIF private key");
        }

        String privKeyStr = decodeStr.substring(2, 66);
        return privKeyStr;

    }
}
