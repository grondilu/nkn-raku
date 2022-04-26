#!/usr/bin/env raku
use Test;
plan 1;

use NKN::Client;

my NKN::Client ($alice, $bob);

await Promise.allof:
  start { $alice = NKN::Client.new: "alice" },
  start { $bob   = NKN::Client.new: "bob"   };

say $alice;
say $bob;

await Promise.allof: |map *.connection.close, $alice, $bob;

# vi: ft=raku
