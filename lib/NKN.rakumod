#!/usr/bin/env raku
unit module NKN;
use NKN::Wallet;

use Digest;
use Digest::SHA;

constant @rpc-servers = (1..30).map: *.fmt: "http://mainnet-seed-%04d.nkn.org:30003";

#use JSON::RPC::Client;
#given JSON::RPC::Client.new: url => @rpc-servers.pick { say .getblock: height => 1; }


# vi: ft=raku
