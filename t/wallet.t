#!/usr/bin/env raku
use Test;
plan 1;

use NKN::Wallet;

use Ed25519;
use Digest::SHA;

constant $password = "foo";

%*ENV<NKN_WALLET_PASSWORD> = $password;

my NKN::Wallet $wallet .= new;


lives-ok { $wallet.private-key }
#is $private-key.seed, $wallet.private-key.seed, "private key succesfully retrieved";

# vi: ft=raku
