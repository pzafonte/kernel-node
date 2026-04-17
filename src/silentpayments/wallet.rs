use std::{
    collections::HashMap,
    io::{self, Read as IoRead, Write as IoWrite},
};

use bitcoin::secp256k1::XOnlyPublicKey;

use super::scanning::FoundPayment;

const WALLET_MAGIC: &[u8; 4] = b"SP01";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl std::fmt::Debug for Outpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut txid_display = self.txid;
        txid_display.reverse();
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}…:{}",
            txid_display[0], txid_display[1], txid_display[2], txid_display[3], self.vout
        )
    }
}

pub struct SpentBy {
    pub txid: [u8; 32],
    pub block_height: u32,
}

pub struct OwnedUtxo {
    pub outpoint: Outpoint,
    pub x_only_pubkey: XOnlyPublicKey,
    pub k: u32,
    pub amount: i64,
    pub block_height: u32,
    pub spent: bool,
    pub spent_by: Option<SpentBy>,
}

/// In-memory wallet tracking silent payment UTXOs.
#[derive(Default)]
pub struct SilentPaymentWallet {
    utxos: HashMap<Outpoint, OwnedUtxo>,
    pub scan_height: u32,
}

impl SilentPaymentWallet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_found_payments(&mut self, payments: &[FoundPayment], block_height: u32) {
        for p in payments {
            let outpoint = Outpoint {
                txid: p.txid,
                vout: p.vout,
            };
            self.utxos.insert(
                outpoint,
                OwnedUtxo {
                    outpoint,
                    x_only_pubkey: p.x_only_pubkey,
                    k: p.k,
                    amount: p.amount,
                    spent: false,
                    spent_by: None,
                    block_height,
                },
            );
        }
        self.scan_height = block_height;
    }

    pub fn mark_spent(
        &mut self,
        txid: &[u8; 32],
        vout: u32,
        spending_txid: &[u8; 32],
        block_height: u32,
    ) -> bool {
        let outpoint = Outpoint { txid: *txid, vout };
        if let Some(utxo) = self.utxos.get_mut(&outpoint) {
            utxo.spent = true;
            utxo.spent_by = Some(SpentBy {
                txid: *spending_txid,
                block_height,
            });
            true
        } else {
            false
        }
    }

    pub fn balance(&self) -> i64 {
        self.utxos
            .values()
            .filter(|u| !u.spent)
            .map(|u| u.amount)
            .sum()
    }

    pub fn unspent_utxos(&self) -> Vec<&OwnedUtxo> {
        self.utxos.values().filter(|u| !u.spent).collect()
    }

    pub fn all_utxos(&self) -> Vec<&OwnedUtxo> {
        self.utxos.values().collect()
    }

    pub fn total_outputs(&self) -> usize {
        self.utxos.len()
    }

    pub fn unspent_count(&self) -> usize {
        self.utxos.values().filter(|u| !u.spent).count()
    }

    pub fn check_for_spends(
        &mut self,
        input_outpoints: &[([u8; 32], [u8; 32], u32)],
        block_height: u32,
    ) -> usize {
        let mut count = 0;
        for &(ref spending_txid, ref prevout_txid, prevout_vout) in input_outpoints {
            if self.mark_spent(prevout_txid, prevout_vout, spending_txid, block_height) {
                count += 1;
            }
        }
        count
    }

    pub fn save<W: IoWrite>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(WALLET_MAGIC)?;
        writer.write_all(&self.scan_height.to_le_bytes())?;
        writer.write_all(&(self.utxos.len() as u32).to_le_bytes())?;

        for utxo in self.utxos.values() {
            writer.write_all(&utxo.outpoint.txid)?;
            writer.write_all(&utxo.outpoint.vout.to_le_bytes())?;
            writer.write_all(&utxo.x_only_pubkey.serialize())?;
            writer.write_all(&utxo.k.to_le_bytes())?;
            writer.write_all(&utxo.amount.to_le_bytes())?;
            writer.write_all(&utxo.block_height.to_le_bytes())?;
            writer.write_all(&[utxo.spent as u8])?;
            match &utxo.spent_by {
                Some(spent_by) => {
                    writer.write_all(&[1u8])?;
                    writer.write_all(&spent_by.txid)?;
                    writer.write_all(&spent_by.block_height.to_le_bytes())?;
                }
                None => {
                    writer.write_all(&[0u8])?;
                }
            }
        }

        Ok(())
    }

    pub fn load<R: IoRead>(reader: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != WALLET_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a silent payment wallet file (bad magic)",
            ));
        }

        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let scan_height = u32::from_le_bytes(buf4);

        reader.read_exact(&mut buf4)?;
        let num_utxos = u32::from_le_bytes(buf4) as usize;

        let mut utxos = HashMap::with_capacity(num_utxos);

        for _ in 0..num_utxos {
            let mut txid = [0u8; 32];
            reader.read_exact(&mut txid)?;
            reader.read_exact(&mut buf4)?;
            let vout = u32::from_le_bytes(buf4);
            let outpoint = Outpoint { txid, vout };

            let mut xonly_bytes = [0u8; 32];
            reader.read_exact(&mut xonly_bytes)?;
            let x_only_pubkey = XOnlyPublicKey::from_slice(&xonly_bytes).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad x-only key: {e}"))
            })?;

            reader.read_exact(&mut buf4)?;
            let k = u32::from_le_bytes(buf4);

            let mut buf8 = [0u8; 8];
            reader.read_exact(&mut buf8)?;
            let amount = i64::from_le_bytes(buf8);

            reader.read_exact(&mut buf4)?;
            let block_height = u32::from_le_bytes(buf4);

            let mut flag = [0u8; 1];
            reader.read_exact(&mut flag)?;
            let spent = flag[0] != 0;

            reader.read_exact(&mut flag)?;
            let spent_by = if flag[0] != 0 {
                let mut spending_txid = [0u8; 32];
                reader.read_exact(&mut spending_txid)?;
                reader.read_exact(&mut buf4)?;
                let spending_height = u32::from_le_bytes(buf4);
                Some(SpentBy {
                    txid: spending_txid,
                    block_height: spending_height,
                })
            } else {
                None
            };

            utxos.insert(
                outpoint,
                OwnedUtxo {
                    outpoint,
                    x_only_pubkey,
                    k,
                    amount,
                    block_height,
                    spent,
                    spent_by,
                },
            );
        }

        Ok(Self { utxos, scan_height })
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = io::BufWriter::new(file);
        self.save(&mut writer)
    }

    pub fn load_from_file(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut reader = io::BufReader::new(file);
        Self::load(&mut reader)
    }
}

pub enum HistoryEntry {
    Received {
        outpoint: Outpoint,
        amount: i64,
        block_height: u32,
    },
    Spent {
        outpoint: Outpoint,
        amount: i64,
        spending_txid: [u8; 32],
        block_height: u32,
    },
}

impl HistoryEntry {
    pub fn block_height(&self) -> u32 {
        match self {
            HistoryEntry::Received { block_height, .. } => *block_height,
            HistoryEntry::Spent { block_height, .. } => *block_height,
        }
    }

    pub fn signed_amount(&self) -> i64 {
        match self {
            HistoryEntry::Received { amount, .. } => *amount,
            HistoryEntry::Spent { amount, .. } => -(*amount),
        }
    }
}

pub fn build_history(wallet: &SilentPaymentWallet) -> Vec<HistoryEntry> {
    let mut entries = Vec::new();

    for utxo in wallet.all_utxos() {
        entries.push(HistoryEntry::Received {
            outpoint: utxo.outpoint,
            amount: utxo.amount,
            block_height: utxo.block_height,
        });

        if let Some(ref spent_by) = utxo.spent_by {
            entries.push(HistoryEntry::Spent {
                outpoint: utxo.outpoint,
                amount: utxo.amount,
                spending_txid: spent_by.txid,
                block_height: spent_by.block_height,
            });
        }
    }

    entries.sort_by(|a, b| {
        a.block_height()
            .cmp(&b.block_height())
            .then_with(|| match (a, b) {
                (HistoryEntry::Received { .. }, HistoryEntry::Spent { .. }) => {
                    std::cmp::Ordering::Less
                }
                (HistoryEntry::Spent { .. }, HistoryEntry::Received { .. }) => {
                    std::cmp::Ordering::Greater
                }
                _ => std::cmp::Ordering::Equal,
            })
    });

    entries
}
