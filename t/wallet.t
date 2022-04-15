#!/usr/bin/env raku
use Test;
plan 1;

use NKN::Wallet;

use Ed25519;
use Digest::SHA;

constant $password = "sézame";

my Ed25519::Key $private-key .= new;
my NKN::Wallet $wallet .= new: :$password, :$private-key; 

is $private-key.seed, $wallet.retrieve-private-key($password).seed, "private key succesfully retrieved";


# vi: ft=raku
