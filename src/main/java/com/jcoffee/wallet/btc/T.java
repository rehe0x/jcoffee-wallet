package com.jcoffee.wallet.btc;

import com.jcoffee.wallet.btc.account.Address;
import com.jcoffee.wallet.btc.account.KeyGenerator;


/**
 * @program jcoffee-wallet 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/03 11:11 
 */
public class T {
    public static void main(String[] args) {
        Address address = KeyGenerator.createAddress();
    }
}
