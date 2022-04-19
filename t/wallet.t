#!/usr/bin/env raku
use Test;
plan 3;

use NKN::Wallet::Encrypted;
class Wallet is NKN::Wallet::Encrypted {}

%*ENV<NKN_WALLET_PASSWORD> = 
constant $password = "foo";

my Wallet $wallet .= new;

lives-ok { $wallet.private-key }
lives-ok { Wallet.new: $wallet.private-key }

ok Wallet.new($wallet.private-key).private-key ~~ $wallet.private-key;

# vi: ft=raku
