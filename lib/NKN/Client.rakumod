#!/usr/bin/env raku
use JSON::RPC::Client;
unit class NKN::Client is JSON::RPC::Client;

use NKN;
use NKN::RPC;
use NKN::Wallet;

use Digest;
use Ed25519;

has Ed25519::Key $.key;
has Str $.identifier;

multi method new(
  Str $identifier = 'anon',
  Ed25519::Key :$key = Ed25519::Key.new,
  Str :$rpc-server = NKN::RPC::servers.pick 
) {
  self.bless:
    :url($rpc-server),
    :$identifier,
    :$key;
}

method wsAddr { self.getwsaddr: :$.address }
  
method public-key { blob-to-hex $!key.point.blob }
method address    { $!identifier ~ '.' ~ $.public-key }

method close {
  ...
}

# vi: ft=raku
