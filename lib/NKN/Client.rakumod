#!/usr/bin/env raku
unit class NKN::Client;

use NKN;
use NKN::Wallet;

use Digest;
use Ed25519;

use Cro::WebSocket::Client;
has Cro::WebSocket::Client $.client;

use Cro::WebSocket::Client::Connection;
has Cro::WebSocket::Client::Connection $.connection;

has Ed25519::Key $.key;
has Str $.identifier;

submethod TWEAK {
  my $node-info = self.wsAddr;
  my Cro::WebSocket::Client $client .= new:
    uri => "ws://$node-info<addr>", :json;
  my $connection = await $client.connect;
  $connection.send:
    { :Action('setClient'), :Addr(self.address) }
  start react {
    whenever $connection.messages -> $message {
      whenever $message.body -> $body {
	# Process the body
	note $body;
      }
    }
  }
  $!connection = $connection;
}
  
multi method new(
  Ed25519::Key :$key = Ed25519::Key.new
) { self.bless: :$key }

multi method new(
  Str $identifier,
  Ed25519::Key :$key = Ed25519::Key.new,
) { self.bless: :$identifier, :$key }

method wsAddr {
  use NKN::RPC;
  use JSON::RPC::Client;
  JSON::RPC::Client
  .new(url => NKN::RPC::servers.pick)
  .getwsaddr: :$.address
}
  
method public-key { blob-to-hex $!key.point.blob }
method address    { $!identifier ?? "$!identifier.$.public-key" !! $.public-key }

# vi: ft=raku
