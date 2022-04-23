#!/usr/bin/env raku
use Test;
plan 1;

use NKN::Client;

my NKN::Client $client .= new;

lives-ok { $client.wsAddr }, "can get websocket address via RPC";

# vi: ft=raku
