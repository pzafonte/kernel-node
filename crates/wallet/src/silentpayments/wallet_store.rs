//! On-disk store for silent payment wallet state.

use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use bitcoin::{hashes::Hash, secp256k1::Scalar, Amount, OutPoint, ScriptBuf, Txid};

use crate::silentpayments::{
    wallet::{Coin, SpentBy},
    Network,
};

// "S"ilent "P"ayments "W"allet "F"ile
const MAGIC: &[u8; 4] = b"SPWF";

const VERSION: u8 = 1;

const HEADER_LEN: u64 = 14;

const H_SCAN_HEIGHT: u64 = 6;
const H_TOTAL_RECORDS: u64 = 10;

const NETWORK_MAINNET: u8 = 0;
const NETWORK_TESTNET: u8 = 1;
const NETWORK_REGTEST: u8 = 2;

const RECORD_LEN: u64 = 184;
const RECORD_SIZE: usize = 184;
const SCRIPT_LEN: usize = 34;

const R_STATUS: usize = 0;
const R_TXID: usize = 1;
const R_VOUT: usize = 33;
const R_VALUE: usize = 37;
const R_SCRIPT: usize = 45;
const R_TWEAK: usize = 79;
const R_LABEL_TAG: usize = 111;
const R_LABEL_SCALAR: usize = 112;
const R_BLOCK_HEIGHT: usize = 144;
const R_SPENT_TXID: usize = 148;
const R_SPENT_HEIGHT: usize = 180;

const STATUS_ACTIVE: u8 = 0;
const STATUS_SPENT: u8 = 1;
const STATUS_TOMBSTONE: u8 = 2;

const LABEL_TAG_NONE: u8 = 0;
const LABEL_TAG_SOME: u8 = 1;

#[derive(Debug)]
pub enum WalletStoreError {
    Io(io::Error),
    BadMagic,
    WrongVersion(u8),
    UnknownNetwork(u8),
    UnknownStatus(u8),
    UnknownLabelTag(u8),
    InvalidScalar,
    NonP2trScript { got: usize },
}

impl fmt::Display for WalletStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::BadMagic => write!(f, "bad magic bytes"),
            Self::WrongVersion(v) => write!(f, "unsupported version: {v}"),
            Self::UnknownNetwork(n) => write!(f, "unknown network byte: {n}"),
            Self::UnknownStatus(s) => write!(f, "unknown record status byte: {s}"),
            Self::UnknownLabelTag(t) => write!(f, "unknown label tag byte: {t}"),
            Self::InvalidScalar => write!(f, "invalid scalar in record"),
            Self::NonP2trScript { got } => {
                write!(f, "script_pubkey is {got} bytes, expected {SCRIPT_LEN}")
            }
        }
    }
}

impl std::error::Error for WalletStoreError {}

impl From<io::Error> for WalletStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
pub struct WalletStore {
    file: File,
    index: HashMap<OutPoint, u64>,
    pub network: Network,
    pub scan_height: u32,
    total_records: u64,
}

impl WalletStore {
    pub fn create(path: &Path, network: Network) -> Result<Self, WalletStoreError> {
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        let mut header = [0u8; HEADER_LEN as usize];
        header[0..4].copy_from_slice(MAGIC);
        header[4] = VERSION;
        header[5] = encode_network(network);
        file.write_all(&header)?;

        Ok(Self {
            file,
            index: HashMap::new(),
            network,
            scan_height: 0,
            total_records: 0,
        })
    }

    pub fn open(path: &Path) -> Result<Self, WalletStoreError> {
        let mut file = File::options().read(true).write(true).open(path)?;

        let mut header = [0u8; HEADER_LEN as usize];
        file.read_exact(&mut header)?;

        if &header[0..4] != MAGIC.as_slice() {
            return Err(WalletStoreError::BadMagic);
        }
        if header[4] != VERSION {
            return Err(WalletStoreError::WrongVersion(header[4]));
        }
        let network = decode_network(header[5])?;
        let scan_height = u32::from_le_bytes(header[6..10].try_into().unwrap());
        let total_records = u32::from_le_bytes(header[10..14].try_into().unwrap()) as u64;

        let mut index = HashMap::with_capacity(total_records as usize);
        let mut buf = [0u8; RECORD_SIZE];

        for i in 0..total_records {
            file.seek(SeekFrom::Start(HEADER_LEN + i * RECORD_LEN))?;
            file.read_exact(&mut buf)?;
            if buf[R_STATUS] == STATUS_TOMBSTONE {
                continue;
            }
            let txid = Txid::from_byte_array(buf[R_TXID..R_TXID + 32].try_into().unwrap());
            let vout = u32::from_le_bytes(buf[R_VOUT..R_VOUT + 4].try_into().unwrap());
            index.insert(OutPoint { txid, vout }, i);
        }

        Ok(Self {
            file,
            index,
            network,
            scan_height,
            total_records,
        })
    }

    pub fn coins(&mut self) -> Result<Vec<(OutPoint, Coin)>, WalletStoreError> {
        let mut result = Vec::with_capacity(self.index.len());
        let mut buf = [0u8; RECORD_SIZE];

        for i in 0..self.total_records {
            self.file
                .seek(SeekFrom::Start(HEADER_LEN + i * RECORD_LEN))?;
            self.file.read_exact(&mut buf)?;
            if buf[R_STATUS] == STATUS_TOMBSTONE {
                continue;
            }
            result.push(decode_record(&buf)?);
        }

        Ok(result)
    }

    // new_coins before newly_spent (same-block receive+spend).
    pub fn apply_scan(
        &mut self,
        height: u32,
        new_coins: &[(OutPoint, Coin)],
        newly_spent: &[(OutPoint, SpentBy)],
    ) -> Result<(), WalletStoreError> {
        if !new_coins.is_empty() {
            let count_before = self.total_records;
            self.file.seek(SeekFrom::Start(
                HEADER_LEN + self.total_records * RECORD_LEN,
            ))?;

            for (outpoint, coin) in new_coins {
                if self.index.contains_key(outpoint) {
                    continue;
                }
                self.file.write_all(&encode_record(outpoint, coin)?)?;
                self.index.insert(*outpoint, self.total_records);
                self.total_records += 1;
            }

            if self.total_records > count_before {
                self.file.seek(SeekFrom::Start(H_TOTAL_RECORDS))?;
                self.file
                    .write_all(&(self.total_records as u32).to_le_bytes())?;
            }
        }

        for (outpoint, spent_by) in newly_spent {
            let Some(&record_idx) = self.index.get(outpoint) else {
                continue;
            };
            let base = HEADER_LEN + record_idx * RECORD_LEN;

            self.file
                .seek(SeekFrom::Start(base + R_SPENT_TXID as u64))?;
            self.file.write_all(&spent_by.txid.to_byte_array())?;
            // No seek: write_all advances the cursor, so this lands at R_SPENT_HEIGHT.
            self.file.write_all(&spent_by.block_height.to_le_bytes())?;

            self.file.seek(SeekFrom::Start(base + R_STATUS as u64))?;
            self.file.write_all(&[STATUS_SPENT])?;
        }

        self.scan_height = height;
        self.file.seek(SeekFrom::Start(H_SCAN_HEIGHT))?;
        self.file.write_all(&height.to_le_bytes())?;

        self.file.sync_data()?;

        Ok(())
    }

    pub fn apply_disconnect(
        &mut self,
        new_height: u32,
        removed: &[OutPoint],
        unspent: &[OutPoint],
    ) -> Result<(), WalletStoreError> {
        for outpoint in removed {
            let Some(record_idx) = self.index.remove(outpoint) else {
                continue;
            };
            let base = HEADER_LEN + record_idx * RECORD_LEN;
            self.file.seek(SeekFrom::Start(base + R_STATUS as u64))?;
            self.file.write_all(&[STATUS_TOMBSTONE])?;
        }

        for outpoint in unspent {
            let Some(&record_idx) = self.index.get(outpoint) else {
                continue;
            };
            let base = HEADER_LEN + record_idx * RECORD_LEN;
            self.file
                .seek(SeekFrom::Start(base + R_SPENT_TXID as u64))?;
            self.file.write_all(&[0u8; 36])?;
            self.file.seek(SeekFrom::Start(base + R_STATUS as u64))?;
            self.file.write_all(&[STATUS_ACTIVE])?;
        }

        self.scan_height = new_height;
        self.file.seek(SeekFrom::Start(H_SCAN_HEIGHT))?;
        self.file.write_all(&new_height.to_le_bytes())?;

        self.file.sync_data()?;

        Ok(())
    }
}

fn encode_network(n: Network) -> u8 {
    match n {
        Network::Mainnet => NETWORK_MAINNET,
        Network::Testnet => NETWORK_TESTNET,
        Network::Regtest => NETWORK_REGTEST,
    }
}

fn decode_network(b: u8) -> Result<Network, WalletStoreError> {
    match b {
        NETWORK_MAINNET => Ok(Network::Mainnet),
        NETWORK_TESTNET => Ok(Network::Testnet),
        NETWORK_REGTEST => Ok(Network::Regtest),
        n => Err(WalletStoreError::UnknownNetwork(n)),
    }
}

fn encode_record(outpoint: &OutPoint, coin: &Coin) -> Result<[u8; RECORD_SIZE], WalletStoreError> {
    let script = coin.script_pubkey.as_bytes();
    if script.len() != SCRIPT_LEN {
        return Err(WalletStoreError::NonP2trScript { got: script.len() });
    }

    let mut buf = [0u8; RECORD_SIZE];

    buf[R_STATUS] = STATUS_ACTIVE;
    buf[R_TXID..R_TXID + 32].copy_from_slice(&outpoint.txid.to_byte_array());
    buf[R_VOUT..R_VOUT + 4].copy_from_slice(&outpoint.vout.to_le_bytes());
    buf[R_VALUE..R_VALUE + 8].copy_from_slice(&coin.value.to_sat().to_le_bytes());
    buf[R_SCRIPT..R_SCRIPT + SCRIPT_LEN].copy_from_slice(script);
    buf[R_TWEAK..R_TWEAK + 32].copy_from_slice(&coin.tweak.to_be_bytes());

    match coin.label {
        Some(scalar) => {
            buf[R_LABEL_TAG] = LABEL_TAG_SOME;
            buf[R_LABEL_SCALAR..R_LABEL_SCALAR + 32].copy_from_slice(&scalar.to_be_bytes());
        }
        None => {
            buf[R_LABEL_TAG] = LABEL_TAG_NONE;
        }
    }

    buf[R_BLOCK_HEIGHT..R_BLOCK_HEIGHT + 4].copy_from_slice(&coin.block_height.to_le_bytes());

    Ok(buf)
}

fn decode_record(buf: &[u8; RECORD_SIZE]) -> Result<(OutPoint, Coin), WalletStoreError> {
    let status = buf[R_STATUS];
    match status {
        STATUS_ACTIVE | STATUS_SPENT => {}
        STATUS_TOMBSTONE => {
            unreachable!("decode_record called on a tombstone; caller must filter")
        }
        other => return Err(WalletStoreError::UnknownStatus(other)),
    }

    let txid = Txid::from_byte_array(buf[R_TXID..R_TXID + 32].try_into().unwrap());
    let vout = u32::from_le_bytes(buf[R_VOUT..R_VOUT + 4].try_into().unwrap());
    let outpoint = OutPoint { txid, vout };

    let value = Amount::from_sat(u64::from_le_bytes(
        buf[R_VALUE..R_VALUE + 8].try_into().unwrap(),
    ));

    let script_pubkey = ScriptBuf::from(buf[R_SCRIPT..R_SCRIPT + SCRIPT_LEN].to_vec());

    let tweak_bytes: [u8; 32] = buf[R_TWEAK..R_TWEAK + 32].try_into().unwrap();
    let tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| WalletStoreError::InvalidScalar)?;

    let label = match buf[R_LABEL_TAG] {
        LABEL_TAG_NONE => None,
        LABEL_TAG_SOME => {
            let label_bytes: [u8; 32] =
                buf[R_LABEL_SCALAR..R_LABEL_SCALAR + 32].try_into().unwrap();
            Some(Scalar::from_be_bytes(label_bytes).map_err(|_| WalletStoreError::InvalidScalar)?)
        }
        other => return Err(WalletStoreError::UnknownLabelTag(other)),
    };

    let block_height =
        u32::from_le_bytes(buf[R_BLOCK_HEIGHT..R_BLOCK_HEIGHT + 4].try_into().unwrap());

    let spent_by = if status == STATUS_SPENT {
        let spent_txid_bytes: [u8; 32] = buf[R_SPENT_TXID..R_SPENT_TXID + 32].try_into().unwrap();
        let spent_height =
            u32::from_le_bytes(buf[R_SPENT_HEIGHT..R_SPENT_HEIGHT + 4].try_into().unwrap());
        Some(SpentBy {
            txid: Txid::from_byte_array(spent_txid_bytes),
            block_height: spent_height,
        })
    } else {
        None
    };

    Ok((
        outpoint,
        Coin {
            value,
            script_pubkey,
            tweak,
            label,
            block_height,
            spent_by,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint_n(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: n as u32,
        }
    }

    fn p2tr_script() -> ScriptBuf {
        let mut bytes = vec![0x51u8, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        ScriptBuf::from(bytes)
    }

    fn dummy_coin() -> Coin {
        Coin {
            value: Amount::from_sat(100_000),
            script_pubkey: p2tr_script(),
            tweak: Scalar::from_be_bytes([7u8; 32]).unwrap(),
            label: None,
            block_height: 800_000,
            spent_by: None,
        }
    }

    #[test]
    fn create_then_open_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let store = WalletStore::create(&path, Network::Regtest).unwrap();
        assert_eq!(store.scan_height, 0);
        assert_eq!(store.total_records, 0);
        drop(store);

        let store = WalletStore::open(&path).unwrap();
        assert_eq!(store.scan_height, 0);
        assert!(matches!(store.network, Network::Regtest));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        WalletStore::create(&path, Network::Regtest).unwrap();
        let result = WalletStore::create(&path, Network::Regtest);
        assert!(matches!(
            result,
            Err(WalletStoreError::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists
        ));
    }

    #[test]
    fn new_coins_persist_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let coin = dummy_coin();

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, coin.clone())], &[]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        assert_eq!(store.scan_height, 100);
        let coins = store.coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].0, op);
        assert_eq!(coins[0].1.value, coin.value);
        assert_eq!(coins[0].1.block_height, coin.block_height);
        assert_eq!(coins[0].1.tweak.to_be_bytes(), coin.tweak.to_be_bytes());
        assert_eq!(coins[0].1.script_pubkey, coin.script_pubkey);
        assert!(coins[0].1.spent_by.is_none());
    }

    #[test]
    fn mark_spent_persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let spending_txid = Txid::from_byte_array([9u8; 32]);

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        store
            .apply_scan(
                101,
                &[],
                &[(
                    op,
                    SpentBy {
                        txid: spending_txid,
                        block_height: 101,
                    },
                )],
            )
            .unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        let coins = store.coins().unwrap();
        assert_eq!(coins.len(), 1);
        let s = coins[0].1.spent_by.as_ref().unwrap();
        assert_eq!(s.txid, spending_txid);
        assert_eq!(s.block_height, 101);
    }

    #[test]
    fn same_block_receive_and_spend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let spending_txid = Txid::from_byte_array([9u8; 32]);

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store
            .apply_scan(
                100,
                &[(op, dummy_coin())],
                &[(
                    op,
                    SpentBy {
                        txid: spending_txid,
                        block_height: 100,
                    },
                )],
            )
            .unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        let coins = store.coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert!(coins[0].1.spent_by.is_some());
    }

    #[test]
    fn disconnect_tombstones_coin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        store.apply_disconnect(99, &[op], &[]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        assert_eq!(store.scan_height, 99);
        assert!(store.coins().unwrap().is_empty());
    }

    #[test]
    fn disconnect_clears_spent_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        store
            .apply_scan(
                101,
                &[],
                &[(
                    op,
                    SpentBy {
                        txid: Txid::from_byte_array([9u8; 32]),
                        block_height: 101,
                    },
                )],
            )
            .unwrap();
        store.apply_disconnect(100, &[], &[op]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        let coins = store.coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert!(coins[0].1.spent_by.is_none());
    }

    #[test]
    fn label_scalar_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let label_scalar = Scalar::from_be_bytes([3u8; 32]).unwrap();
        let coin = Coin {
            label: Some(label_scalar),
            ..dummy_coin()
        };

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, coin)], &[]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        let coins = store.coins().unwrap();
        let loaded_label = coins[0].1.label.as_ref().unwrap();
        assert_eq!(loaded_label.to_be_bytes(), label_scalar.to_be_bytes());
    }

    #[test]
    fn open_rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        std::fs::write(&path, b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        assert!(matches!(
            WalletStore::open(&path),
            Err(WalletStoreError::BadMagic)
        ));
    }

    #[test]
    fn open_rejects_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        let mut bytes = MAGIC.to_vec();
        bytes.push(99); // version
        bytes.push(NETWORK_REGTEST);
        bytes.extend_from_slice(&[0u8; 8]); // scan_height + total_records
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            WalletStore::open(&path),
            Err(WalletStoreError::WrongVersion(99))
        ));
    }

    #[test]
    fn apply_scan_is_idempotent_for_duplicate_coins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        assert_eq!(store.coins().unwrap().len(), 1);
    }

    #[test]
    fn non_p2tr_script_is_rejected_at_encode() {
        let coin = Coin {
            script_pubkey: ScriptBuf::from(vec![0u8; 25]), // not 34 bytes
            ..dummy_coin()
        };
        assert!(matches!(
            encode_record(&outpoint_n(1), &coin),
            Err(WalletStoreError::NonP2trScript { got: 25 })
        ));
    }

    #[test]
    fn multi_record_indexing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op_a = outpoint_n(1);
        let op_b = outpoint_n(2);
        let spending_txid = Txid::from_byte_array([9u8; 32]);

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store
            .apply_scan(100, &[(op_a, dummy_coin()), (op_b, dummy_coin())], &[])
            .unwrap();
        store
            .apply_scan(
                101,
                &[],
                &[(
                    op_b,
                    SpentBy {
                        txid: spending_txid,
                        block_height: 101,
                    },
                )],
            )
            .unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        let coins = store.coins().unwrap();
        assert_eq!(coins.len(), 2);

        assert_eq!(coins[0].0, op_a);
        assert_eq!(coins[1].0, op_b);

        assert!(coins[0].1.spent_by.is_none());
        let b_spent = coins[1].1.spent_by.as_ref().unwrap();
        assert_eq!(b_spent.txid, spending_txid);
        assert_eq!(b_spent.block_height, 101);
    }

    #[test]
    fn disconnect_is_idempotent_for_already_removed_coins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let op = outpoint_n(1);
        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store.apply_scan(100, &[(op, dummy_coin())], &[]).unwrap();
        store.apply_disconnect(99, &[op], &[]).unwrap();
        store.apply_disconnect(99, &[op], &[]).unwrap();
        drop(store);

        let mut store = WalletStore::open(&path).unwrap();
        assert_eq!(store.scan_height, 99);
        assert!(store.coins().unwrap().is_empty());
    }

    #[test]
    fn open_rejects_truncated_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        std::fs::write(&path, b"SPWF\x01").unwrap();
        assert!(matches!(
            WalletStore::open(&path),
            Err(WalletStoreError::Io(_))
        ));
    }

    #[test]
    fn open_rejects_truncated_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store
            .apply_scan(100, &[(outpoint_n(1), dummy_coin())], &[])
            .unwrap();
        drop(store);

        let truncated_len = HEADER_LEN + RECORD_LEN / 2;
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(truncated_len).unwrap();
        drop(f);

        assert!(matches!(
            WalletStore::open(&path),
            Err(WalletStoreError::Io(_))
        ));
    }

    #[test]
    fn coins_rejects_unknown_status_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let mut store = WalletStore::create(&path, Network::Regtest).unwrap();
        store
            .apply_scan(100, &[(outpoint_n(1), dummy_coin())], &[])
            .unwrap();
        drop(store);

        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN + R_STATUS as u64))
            .unwrap();
        f.write_all(&[99]).unwrap();
        drop(f);

        let mut store = WalletStore::open(&path).unwrap();
        assert!(matches!(
            store.coins(),
            Err(WalletStoreError::UnknownStatus(99))
        ));
    }
}
