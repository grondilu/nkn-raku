#!/usr/bin/env raku
unit module NKN::RPC;

our constant servers = (1..30).fmt("http://mainnet-seed-%04d.nkn.org:30003").words.cache;

# vi: ft=raku
