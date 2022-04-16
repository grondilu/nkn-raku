#!/usr/bin/env raku
unit class NKN::Wallet;
use Base58;

use Digest;
use Digest::SHA;
use Digest::RIPEMD;

use Ed25519;

our constant prefix = blob8.new: 0x02, 0xb8, 0x25;

has Blob (
  $.password-hash,
  $.initialisation-vector,
  $.private-key-encrypted,
  $.master-key,
  $.program-hash,
  $.contract-data
);
has Str $.version = '0.0.1';
has Str $.address;

our sub aec-cbc-enc256(
  blob8 :$data,
  blob8 :$key,
  blob8 :$iv,
  Bool  :$decode
  ) is export {
  my ($hex-key, $hex-iv) = ($key, $iv).map({$_».fmt("%02x").join});
  given run «openssl enc
    -aes-256-cbc {$decode ?? '-d' !! '-e'}
    -K $hex-key -iv $hex-iv», :in, :out, :bin {
    .in.write: $data;
    .in.close;
    return .out.slurp: :close;
  }
}

multi method new() {
  LEAVE { run <stty echo>; print "\n" }
  run <stty -echo>;
  my $password = prompt "Enter password: ";
  die "password input mismatch" unless $password eq prompt "\nEnter password again: ";
  print "\n";
  samewith $password;
}
multi method new(Str $password) {
  samewith $password, :private-key(Ed25519::Key.new)
}
multi method new(Str $password, blob8 :$private-key) {
  samewith $password, :private-key(Ed25519::Key.new: :$private-key)
}
multi method new(Str $password, Ed25519::Key :$private-key) {
  my $password-key = sha256 sha256 $password.encode("utf8");
  my $master-key-unencrypted = blob8.new: (^256).roll(32);
  my $initialisation-vector = blob8.new: (^256).roll(16);
  my $signature-script = blob8.new(0x20) ~ $private-key.point.blob ~ blob8.new(0xAC);
  my $program-hash = rmd160 sha256 $signature-script;
  my $address = Base58::encode $_ ~ sha256(sha256 $_).subbuf(0, 4) given prefix ~ $program-hash;
  my $contract-data = [~]
    $signature-script,
    blob8.new(0),
    $program-hash,
    rmd160 sha256 $private-key.point.blob
  ;
  
  self.bless:
    password-hash => sha256($password-key),
    master-key => aec-cbc-enc256(
      data => $master-key-unencrypted,
      key => $password-key,
      iv => $initialisation-vector
    ),
    private-key-encrypted => aec-cbc-enc256(
      data => $private-key.seed,
      key => $master-key-unencrypted,
      iv => $initialisation-vector
    ),
    :$address,
    :$program-hash,
    :$contract-data,
    :$initialisation-vector;
}

method private-key {
  my $password = %*ENV<NKN_WALLET_PASSWORD> ||
  { LEAVE { run <stty echo>; print "\n" }; run <stty -echo>; prompt "password: " }();
  die "wrong password ($password)" unless sha256(sha256(sha256 $password)) eq $!password-hash;
  my $master-key-unencrypted = aec-cbc-enc256
    data => $!master-key,
    key => sha256(sha256 $password),
    iv => $!initialisation-vector,
    :decode
  ;
  Ed25519::Key.new: aec-cbc-enc256
    data => $!private-key-encrypted,
    key => $master-key-unencrypted,
    iv => $!initialisation-vector,
    :decode
  ;
}

method to-JSON {
  qq:to/END/;
  \{
    "PasswordHash": "{blob-to-hex $!password-hash}",
    "IV": "{blob-to-hex $!initialisation-vector}",
    "MasterKey": "{blob-to-hex $!master-key}",
    "Version": "$!version",
    "Address": "$!address",
    "ProgramHash": "{blob-to-hex $!program-hash}",
    "PrivateKeyEncrypted": "{blob-to-hex $!private-key-encrypted}",
    "ContractData": "{blob-to-hex $!contract-data}"
  \}
  END
}

method gist { self.to-JSON }
