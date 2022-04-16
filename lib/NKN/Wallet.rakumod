#!/usr/bin/env raku
unit class NKN::Wallet;
use Base58;

use Digest;
use Digest::SHA;
use Digest::RIPEMD;

use Crypt::LibScrypt;
use Ed25519;

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

our constant prefix = blob8.new: 0x02, 0xb8, 0x25;

sub password-key(Str $password, Blob $salt) { sha256 $password.encode ~ $salt }

has Blob (
  $.initialisation-vector,
  $!private-key,
  $!master-key,
  $.program-hash,
  $.salt
);
has Str $.version = 'experimental';
has Str ($.scrypt-hash, $.address);

submethod BUILD(
  :$password-key,
  :$private-key,
  :$!salt,
  :$!scrypt-hash,
  :$!address,
  :$!program-hash,
  :$!initialisation-vector
) {
  my $master-key = blob8.new((^256).roll(32));
  $!master-key = aec-cbc-enc256(
    data => $master-key,
    key => $password-key,
    iv => $!initialisation-vector
  );
  $!private-key = aec-cbc-enc256(
    data => $private-key.seed,
    key => $master-key,
    iv => $!initialisation-vector
  );
}
multi method new() { samewith Ed25519::Key.new }
multi method new(blob8 $private-key) { samewith Ed25519::Key.new: :$private-key }

multi method new(Ed25519::Key $private-key) {
  my $password = %*ENV<NKN_WALLET_PASSWORD> || sub {
    LEAVE { run <stty echo>; print "\n" }
    run <stty -echo>;
    my $password = prompt "Enter password:";
    die "password input mismatch" unless $password eq prompt "\nEnter password again:";
    return $password;
  }();
  my blob8 $salt .= new: (^256).roll(8);
  my $signature-script = blob8.new(0x20) ~ $private-key.point.blob ~ blob8.new(0xAC);
  my $program-hash = rmd160 sha256 $signature-script;
  my $address = Base58::encode $_ ~ sha256(sha256 $_).subbuf(0, 4) given prefix ~ $program-hash;
 
  self.bless:
    :$salt, :$private-key, :$signature-script, :$program-hash, :$address,
    password-key => password-key($password, $salt),
    scrypt-hash => scrypt-hash($password),
    initialisation-vector => blob8.new((^256).roll(16));
  
}

method master-key {
  my $password = %*ENV<NKN_WALLET_PASSWORD> ||
  { LEAVE { run <stty echo>; print "\n" }; run <stty -echo>; prompt "password: " }();
  die "wrong password" unless scrypt-verify($!scrypt-hash, $password);
  aec-cbc-enc256
    data => $!master-key,
    key => password-key($password, $!salt),
    iv => $!initialisation-vector,
    :decode
}

method private-key {
  Ed25519::Key.new: aec-cbc-enc256
    data => $!private-key,
    key => $.master-key,
    iv => $!initialisation-vector,
    :decode
}

method to-JSON {
  qq:to/END/;
  \{
    "ScryptHash": "$!scrypt-hash",
    "Salt": "{blob-to-hex $!salt}",
    "IV": "{blob-to-hex $!initialisation-vector}",
    "MasterKey": "{blob-to-hex $!master-key}",
    "Version": "$!version",
    "Address": "$!address",
    "ProgramHash": "{blob-to-hex $!program-hash}",
    "PrivateKeyEncrypted": "{blob-to-hex $!private-key}"
  \}
  END
}

method gist { self.to-JSON }
