#!/usr/bin/env raku
unit role NKN::Wallet;

use Ed25519;

has Str $.version = 'grondilu\'s (experimental)';

method private-key returns Ed25519::Key {...}
method point returns Ed25519::Point { self.private-key.point }
method signature-script returns blob8 {
    blob8.new(0x20) ~ self.point.blob ~ blob8.new(0xAC)
}
method program-hash returns blob8 {
  use Digest::SHA;
  use Digest::RIPEMD;

  blob8.new: rmd160 sha256 self.signature-script
}
method address returns Str {
  my $prefix = blob8.new: 0x02, 0xb8, 0x25;
  use Base58;
  use Digest::SHA;
  Base58::encode $_ ~ sha256(sha256 $_).subbuf(0, 4) given $prefix ~ self.program-hash
}

