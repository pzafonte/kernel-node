use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use bitcoin::secp256k1::{Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Txid};
use bitcoinkernel::prelude::{TransactionExt, TxInExt, TxOutPointExt, TxidExt};

use crate::silentpayments::scanning::scan_block_inner;
use crate::silentpayments::{build_receiver, Network, Receiver};

#[derive(Debug)]
pub struct SilentPaymentKeys {
    pub receiver: Receiver,
    pub scan_key: SecretKey,
}

#[derive(Debug, Clone)]
pub struct SpentBy {
    pub txid: Txid,
    pub block_height: u32,
}

#[derive(Debug, Clone)]
pub struct Coin {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub tweak: Scalar,
    pub label: Option<Scalar>,
    pub block_height: u32,
    pub spent_by: Option<SpentBy>,
}

#[derive(Debug, Default)]
pub struct BlockScanResult {
    pub found: usize,
    pub new_coins: Vec<(OutPoint, Coin)>,
    pub newly_spent: Vec<(OutPoint, SpentBy)>,
    pub scan_height: u32,
}

#[derive(Debug, Default)]
pub struct DisconnectResult {
    pub removed: Vec<OutPoint>,
    pub unspent: Vec<OutPoint>,
}

pub enum HistoryEntry {
    Received {
        outpoint: OutPoint,
        value: Amount,
        block_height: u32,
    },
    Spent {
        outpoint: OutPoint,
        value: Amount,
        spent_at: u32,
    },
}

impl fmt::Display for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryEntry::Received {
                outpoint,
                value,
                block_height,
            } => write!(
                f,
                "recv {}:{} {} sats at {}",
                outpoint.txid,
                outpoint.vout,
                value.to_sat(),
                block_height
            ),
            HistoryEntry::Spent {
                outpoint,
                value,
                spent_at,
            } => write!(
                f,
                "spent {}:{} {} sats at {}",
                outpoint.txid,
                outpoint.vout,
                value.to_sat(),
                spent_at
            ),
        }
    }
}

#[derive(Debug)]
pub struct Wallet {
    pub scan_height: u32,
    pub keys: Option<SilentPaymentKeys>,
    pub spend_key: Option<PublicKey>,
    pub network: Network,
    utxos: HashMap<OutPoint, Coin>,
}

impl Wallet {
    pub fn new(network: Network) -> Self {
        Self {
            scan_height: 0,
            keys: None,
            spend_key: None,
            network,
            utxos: HashMap::new(),
        }
    }

    pub fn import_keys(
        &mut self,
        scan_key: SecretKey,
        spend_xonly: XOnlyPublicKey,
    ) -> Result<(), ::silentpayments::Error> {
        let spend_pub = PublicKey::from_x_only_public_key(spend_xonly, Parity::Even);
        let receiver = build_receiver(&scan_key, spend_pub, self.network)?;
        self.spend_key = Some(spend_pub);
        self.keys = Some(SilentPaymentKeys { receiver, scan_key });
        Ok(())
    }

    pub fn scan_block(
        &mut self,
        kernel_block: bitcoinkernel::Block,
        spent_outputs: bitcoinkernel::BlockSpentOutputs,
        block_height: u32,
    ) -> BlockScanResult {
        let Some(keys) = self.keys.as_ref() else {
            return BlockScanResult {
                found: 0,
                new_coins: Vec::new(),
                newly_spent: Vec::new(),
                scan_height: block_height,
            };
        };
        let receiver = keys.receiver.clone();
        let scan_key = keys.scan_key;

        let new_coins = scan_block_inner(
            &receiver,
            &scan_key,
            &kernel_block,
            spent_outputs,
            block_height,
        );
        let found = new_coins.len();

        for (outpoint, coin) in &new_coins {
            self.utxos.insert(*outpoint, coin.clone());
        }

        let mut newly_spent = Vec::new();
        for kernel_tx in kernel_block.transactions() {
            let spending_txid = Txid::from_byte_array(kernel_tx.txid().to_bytes());
            for input in kernel_tx.inputs() {
                let kop = input.outpoint();
                let prev = OutPoint {
                    txid: Txid::from_byte_array(kop.txid().to_bytes()),
                    vout: kop.index(),
                };
                if let Some(utxo) = self.utxos.get_mut(&prev) {
                    let spent_by = SpentBy {
                        txid: spending_txid,
                        block_height,
                    };
                    utxo.spent_by = Some(spent_by.clone());
                    newly_spent.push((prev, spent_by));
                }
            }
        }

        self.scan_height = block_height;
        BlockScanResult {
            found,
            new_coins,
            newly_spent,
            scan_height: block_height,
        }
    }

    pub fn process_disconnect(&mut self, kernel_block: bitcoinkernel::Block) -> DisconnectResult {
        let block_txids: HashSet<Txid> = kernel_block
            .transactions()
            .map(|tx| Txid::from_byte_array(tx.txid().to_bytes()))
            .collect();

        let mut removed = Vec::new();
        self.utxos.retain(|outpoint, _| {
            if block_txids.contains(&outpoint.txid) {
                removed.push(*outpoint);
                false
            } else {
                true
            }
        });

        let mut unspent = Vec::new();
        for (outpoint, utxo) in self.utxos.iter_mut() {
            if let Some(ref s) = utxo.spent_by {
                if block_txids.contains(&s.txid) {
                    utxo.spent_by = None;
                    unspent.push(*outpoint);
                }
            }
        }

        DisconnectResult { removed, unspent }
    }

    pub fn restore(&mut self, scan_height: u32, coins: impl IntoIterator<Item = (OutPoint, Coin)>) {
        self.scan_height = scan_height;
        self.utxos.extend(coins);
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.values().filter(|u| u.spent_by.is_none()).count()
    }

    pub fn receive_address(&self) -> Option<String> {
        self.keys
            .as_ref()
            .map(|k| k.receiver.get_receiving_address().to_string())
    }

    pub fn balance(&self) -> Amount {
        self.utxos
            .values()
            .filter(|u| u.spent_by.is_none())
            .map(|u| u.value)
            .fold(Amount::ZERO, |acc, v| acc + v)
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        let mut entries: Vec<HistoryEntry> = self
            .utxos
            .iter()
            .flat_map(|(outpoint, utxo)| {
                let mut v = vec![HistoryEntry::Received {
                    outpoint: *outpoint,
                    value: utxo.value,
                    block_height: utxo.block_height,
                }];
                if let Some(ref s) = utxo.spent_by {
                    v.push(HistoryEntry::Spent {
                        outpoint: *outpoint,
                        value: utxo.value,
                        spent_at: s.block_height,
                    });
                }
                v
            })
            .collect();

        entries.sort_by_key(|e| match e {
            HistoryEntry::Received { block_height, .. } => *block_height,
            HistoryEntry::Spent { spent_at, .. } => *spent_at,
        });
        entries
    }
}
