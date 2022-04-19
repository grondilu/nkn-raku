#!/usr/bin/env raku
use NKN::Wallet;
unit class NKN::Wallet::Encrypted does NKN::Wallet;

use Ed25519;
has Ed25519::Point $.point;

use Crypt::LibScrypt;

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

sub password-key(Str $password, blob8 $salt) {
  use Digest::SHA;
  sha256 $password.encode ~ $salt
}

has blob8 (
  $.master-key, $.seed,
  $.initialisation-vector, $.salt
);
has Str $.scrypt-hash;

method master-key {
  my $password = %*ENV<NKN_WALLET_PASSWORD> ||
  { LEAVE { run <stty echo>; print "\n" }; run <stty -echo>; prompt "password: " }();
  die "wrong password" unless scrypt-verify($!scrypt-hash, $password);
  blob8.new:
    aec-cbc-enc256
      data => $!master-key,
      key  => password-key($password, $!salt),
      iv   => $!initialisation-vector,
      :decode
}

method private-key {
  Ed25519::Key.new:
    aec-cbc-enc256
      data => $!seed,
      key  => $.master-key,
      iv   => $!initialisation-vector,
      :decode
}

submethod BUILD(
  :$!salt,
  :$!initialisation-vector,
  :$master-key,
  Ed25519::Key :$private-key
) {
  my $password = %*ENV<NKN_WALLET_PASSWORD> || sub {
    LEAVE { run <stty echo>; print "\n" }
    run <stty -echo>;
    my $password = prompt "Enter password:";
    die "password input mismatch" unless $password eq prompt "\nEnter password again:";
    return $password;
  }();
  $!scrypt-hash = scrypt-hash $password;
  $!master-key = aec-cbc-enc256
    data => $master-key,
    key => password-key($password, $!salt),
    iv => $!initialisation-vector
  ;
  $!point = $private-key.point;
  $!seed = aec-cbc-enc256
    data => $private-key.seed,
    key => $master-key,
    iv => $!initialisation-vector,
  ;
}

multi method new(Ed25519::Key $private-key = Ed25519::Key.new) {
  my blob8 $master-key .= new: (^256).roll: 32;
  my blob8 $salt .= new: (^256).roll(8);
  my blob8 $initialisation-vector .= new: (^256).roll(16);
  self.bless:
    :$salt, :$initialisation-vector,
    :$master-key, :$private-key;
}

method to-JSON {
  use JSON::Tiny;
  sub blob2hex($b) { $b».fmt("%02x").join }
  to-json {
    ScryptHash    => $!scrypt-hash,
    IV            => blob2hex($!initialisation-vector),
    Salt          => blob2hex($!salt),
    MasterKey     => blob2hex($!master-key),
    Version       => $!version,
    Address       => $.address,
    SeedEncrypted => blob2hex($!seed)
  }
}
    
