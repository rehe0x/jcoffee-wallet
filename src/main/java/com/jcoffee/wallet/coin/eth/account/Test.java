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
        Account account = KeyGenerator.generateAccount("AD986F074F71EB8C9C003EBEAB0EC14918AA057CA1411B4574011FDD159FF8FC");
        System.out.println(account.toString());
    }
}
