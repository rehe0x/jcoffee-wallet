package com.jcoffee.wallet.coin.eth.account;

import com.jcoffee.wallet.common.Account;

/**
 * @program jcoffee-wallet 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/03 17:27 
 */
public class Test {
    public static void main(String[] args) {
        Account account = KeyGenerator.createAddress();
        System.out.println(account.ToString());
    }
}
