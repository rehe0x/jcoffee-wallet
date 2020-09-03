package com.jcoffee.wallet.btc.account;
/**
 * @program blockchain_study 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/02 16:31 
 */
public class Address {
    private String privkey;
    private String pubkey;
    private String address;
    public Address() {
        Reset();
    }

    public Address(String privkey, String pubkey, String address) {
        this.privkey = privkey;
        this.pubkey = pubkey;
        this.address = address;
    }

    public void Reset() {
        this.privkey = null;
        this.pubkey = null;
        this.address = null;
    }
    public void SetPrivKey(String privkey) {
        this.privkey = privkey;
    }

    public void SetPubKey(String pubkey) {
       this.pubkey = pubkey;
    }

    public void SetAddress(String address) {
        this.address = address;
    }

     public String ToString() {
      return "{\n"

         + "\t privkey:" + this.privkey+"\n"

         + "\t pubkey :" + this.pubkey+"\n"

         + "\t address:" + this.address + "\n"

         + "}\n";

     }


}