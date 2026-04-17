@0xf1a2b3c4d5e6f789;

interface Wallet {
    importKeys @0 (scanKey :Data, spendKey :Data) -> (success :Bool, message :Text);
    getBalance @1 () -> (balance :Int64, scanHeight :UInt32, utxoCount :UInt32);
    getHistory @2 () -> (history :Text);
}
