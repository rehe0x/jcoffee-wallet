package com.jcoffee.wallet.coin.btc.account;

import com.jcoffee.wallet.common.Account;


/**
 * @program jcoffee-wallet 
 * @description:  
 * @author: Horng 
 * @create: 2020/09/03 11:11 
 */
public class Test {
    public static void main(String[] args) {
        Account account = KeyGenerator.generateAccount("KzNEbS7Dnbs6uvs2qC7M8xNNWa6dUvdGTwLjC1wTa2P4m1vSDjFD");
        System.out.println(account.toString());
    }
}
