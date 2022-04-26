# nkn-raku
[NKN](http://nkn.org) in [raku](http://raku.org).

## Synopsis

```raku
use NKN;

say my NKN::Wallet::Encrypted $wallet .= new; 

say $wallet.private-key.sign: "Hello, world!";

```


