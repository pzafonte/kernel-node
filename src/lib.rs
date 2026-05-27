use ::bitcoin::Network;
use log::{error, info, warn};
use p2p::dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use wallet::silentpayments::{Network as SpNetwork, Wallet, WalletStore};

use crate::logging::Category;

pub mod daemonize;
pub mod ext;
pub mod ipc;
pub mod peer;

pub mod logging {
    pub struct Category;

    impl Category {
        pub const KERNEL: &str = "kernel";
        pub const NET: &str = "net";
        pub const WALLET: &str = "wallet";
        pub const IPC: &str = "ipc";
        pub const NODE: &str = "node";
    }
}

pub enum ScanEvent {
    Connected {
        block_height: u32,
        block: bitcoinkernel::Block,
        spent_outputs: bitcoinkernel::BlockSpentOutputs,
    },
    Disconnected {
        block: bitcoinkernel::Block,
        block_height: u32,
    },
}

#[derive(Clone)]
pub struct FatalShutdown {
    triggered: Arc<AtomicBool>,
    tx: mpsc::Sender<()>,
}

impl FatalShutdown {
    pub fn new(tx: mpsc::Sender<()>) -> Self {
        Self {
            triggered: Arc::new(AtomicBool::new(false)),
            tx,
        }
    }

    pub fn trigger(&self, target: &str, message: impl std::fmt::Display) {
        error!(target: target, "{}", message);
        if !self.triggered.swap(true, Ordering::SeqCst) {
            self.tx.send(()).expect("failed to send shutdown signal");
        }
    }
}

#[derive(Debug)]
pub struct WalletState {
    pub wallet: Wallet,
    pub store: Option<WalletStore>,
    pub store_path: PathBuf,
}

impl WalletState {
    pub fn new(wallet: Wallet, store: Option<WalletStore>, store_path: PathBuf) -> Self {
        Self {
            wallet,
            store,
            store_path,
        }
    }

    pub fn open_or_new(network: SpNetwork, store_path: PathBuf) -> Self {
        let mut wallet = Wallet::new(network);

        if !store_path.exists() {
            return Self::new(wallet, None, store_path);
        }

        let store = match WalletStore::open(&store_path) {
            Ok(s) if s.network != wallet.network => {
                warn!(
                    target: Category::WALLET,
                    "Wallet store at {} is for {:?} but wallet is configured for {:?}; ignoring store",
                    store_path.display(),
                    s.network,
                    wallet.network
                );
                None
            }
            Ok(mut s) => match s.coins() {
                Ok(coins) => {
                    let restored_count = coins.len();
                    wallet.restore(s.scan_height, coins);
                    info!(
                        target: Category::WALLET,
                        "Restored wallet from store: scan_height={}, coins={}",
                        s.scan_height,
                        restored_count
                    );
                    Some(s)
                }
                Err(e) => {
                    warn!(
                        target: Category::WALLET,
                        "Failed to load coins from wallet store at {}: {e}",
                        store_path.display()
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    target: Category::WALLET,
                    "Failed to open wallet store at {}: {e}",
                    store_path.display()
                );
                None
            }
        };
        Self::new(wallet, store, store_path)
    }

    pub fn ensure_store(&mut self) {
        if self.store.is_some() {
            return;
        }
        let result = if self.store_path.exists() {
            WalletStore::open(&self.store_path)
        } else {
            WalletStore::create(&self.store_path, self.wallet.network)
        };
        match result {
            Ok(s) if s.network != self.wallet.network => {
                warn!(
                    target: Category::WALLET,
                    "Wallet store at {} is for {:?} but wallet is configured for {:?}; leaving store detached, scans will not persist",
                    self.store_path.display(),
                    s.network,
                    self.wallet.network
                );
            }
            Ok(s) => {
                self.store = Some(s);
            }
            Err(e) => {
                warn!(
                    target: Category::WALLET,
                    "Failed to open or create wallet store at {}: {e}",
                    self.store_path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod wallet_state_tests {
    use super::*;
    use wallet::silentpayments::Network as SpNetwork;

    fn fresh_wallet(network: SpNetwork) -> Wallet {
        Wallet::new(network)
    }

    #[test]
    fn ensure_store_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        assert!(!path.exists());

        let mut wallet_state =
            WalletState::new(fresh_wallet(SpNetwork::Regtest), None, path.clone());
        wallet_state.ensure_store();

        assert!(wallet_state.store.is_some(), "store should be set");
        assert!(path.exists(), "file should exist on disk");
    }

    #[test]
    fn ensure_store_opens_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        drop(WalletStore::create(&path, SpNetwork::Regtest).unwrap());

        let mut wallet_state = WalletState::new(fresh_wallet(SpNetwork::Regtest), None, path);
        wallet_state.ensure_store();
        assert!(wallet_state.store.is_some());
    }

    #[test]
    fn ensure_store_is_noop_when_already_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let mut wallet_state = WalletState::new(fresh_wallet(SpNetwork::Regtest), None, path);
        wallet_state.ensure_store();
        let first_ptr = wallet_state.store.as_ref().unwrap() as *const _;

        wallet_state.ensure_store();
        let second_ptr = wallet_state.store.as_ref().unwrap() as *const _;

        assert_eq!(first_ptr, second_ptr, "store should not be replaced");
    }

    #[test]
    fn ensure_store_refuses_mismatched_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        drop(WalletStore::create(&path, SpNetwork::Regtest).unwrap());

        let mut wallet_state = WalletState::new(fresh_wallet(SpNetwork::Mainnet), None, path);
        wallet_state.ensure_store();

        assert!(
            wallet_state.store.is_none(),
            "store should not attach on network mismatch"
        );
    }

    #[test]
    fn open_or_new_fresh_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        assert!(!path.exists());

        let wallet_state = WalletState::open_or_new(SpNetwork::Regtest, path);
        assert!(
            wallet_state.store.is_none(),
            "no file → store should be None"
        );
        assert_eq!(wallet_state.wallet.scan_height, 0);
    }

    #[test]
    fn open_or_new_restores_from_existing_file() {
        use bitcoin::secp256k1::Scalar;
        use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Txid};
        use wallet::silentpayments::{Coin, SpentBy};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let mut p2tr = vec![0x51u8, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        let coin = Coin {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from(p2tr),
            tweak: Scalar::from_be_bytes([7u8; 32]).unwrap(),
            label: None,
            block_height: 100,
            spent_by: None::<SpentBy>,
        };
        {
            let mut s = WalletStore::create(&path, SpNetwork::Regtest).unwrap();
            s.apply_scan(100, &[(outpoint, coin.clone())], &[]).unwrap();
        }

        let wallet_state = WalletState::open_or_new(SpNetwork::Regtest, path);
        assert!(wallet_state.store.is_some(), "store should attach");
        assert_eq!(wallet_state.wallet.scan_height, 100);
        assert_eq!(wallet_state.wallet.balance(), Amount::from_sat(50_000));
        assert_eq!(wallet_state.wallet.utxo_count(), 1);
    }

    #[test]
    fn open_or_new_falls_back_when_file_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        std::fs::write(&path, b"GARBAGE").unwrap();

        let wallet_state = WalletState::open_or_new(SpNetwork::Regtest, path);
        assert!(
            wallet_state.store.is_none(),
            "corrupt file → store should be None"
        );
        assert_eq!(wallet_state.wallet.scan_height, 0);
    }

    #[test]
    fn open_or_new_falls_back_on_network_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.bin");
        drop(WalletStore::create(&path, SpNetwork::Regtest).unwrap());

        let wallet_state = WalletState::open_or_new(SpNetwork::Mainnet, path);
        assert!(
            wallet_state.store.is_none(),
            "network mismatch should leave store detached"
        );
    }
}

pub fn resolve_seeds(network: Network) -> Vec<IpAddr> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let format_hostname = |host: &str| format!("{host}:53");
    let seeds: Vec<String> = match network {
        Network::Bitcoin => BITCOIN_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Signet => SIGNET_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Testnet => TESTNET3_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Testnet4 => TESTNET4_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Regtest => Vec::new(),
    };
    let mut results = Vec::new();
    for host in seeds {
        let peers = rt.block_on(async move {
            tokio::net::lookup_host(host)
                .await
                .map(|sockets| sockets.map(|socket| socket.ip()).collect())
                .unwrap_or(Vec::new())
        });
        results.extend(peers);
    }
    results
}

capnp::generated_code!(pub mod server_capnp);
capnp::generated_code!(pub mod wallet_capnp);
