package com.jcoffee.wallet.common;
/**
 * @program jcoffee-wallet
 * @description:  
 * @author: Horng 
 * @create: 2020/09/02 16:31 
 */
public class Account {
    private String privkey;
    private String pubkey;
    private String address;
    public Account() {
    }
    public Account(String privkey, String pubkey, String address) {
        this.privkey = privkey;
        this.pubkey = pubkey;
        this.address = address;
    }
     @Override
     public String toString() {
      return "{\n"

         + "\t privkey:" + this.privkey+"\n"

         + "\t pubkey :" + this.pubkey+"\n"

         + "\t address:" + this.address + "\n"

         + "}\n";

     }


}
