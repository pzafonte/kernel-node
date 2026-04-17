use std::sync::{mpsc, Arc, Mutex};

use crate::server_capnp;
use crate::silentpayments::{build_history, HistoryEntry, ScanKey, SilentPaymentWallet, SpendKey};
use crate::wallet_capnp;

#[derive(Clone)]
pub struct WalletState {
    pub wallet: Arc<Mutex<SilentPaymentWallet>>,
    pub scan_key: Arc<Mutex<Option<ScanKey>>>,
    pub spend_key: Arc<Mutex<Option<SpendKey>>>,
}

impl WalletState {
    pub fn new() -> Self {
        Self {
            wallet: Arc::new(Mutex::new(SilentPaymentWallet::new())),
            scan_key: Arc::new(Mutex::new(None)),
            spend_key: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct IpcInterface {
    tx: mpsc::Sender<()>,
}

impl IpcInterface {
    pub fn new(tx: mpsc::Sender<()>) -> Self {
        Self { tx }
    }
}

impl server_capnp::server::Server for IpcInterface {
    async fn echo(
        self: capnp::capability::Rc<Self>,
        params: server_capnp::server::EchoParams,
        mut results: server_capnp::server::EchoResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?.get_msg()?;
        let msg = request.to_string()?;
        results.get().set_reply(msg);
        Ok(())
    }

    async fn shutdown(
        self: capnp::capability::Rc<Self>,
        _: server_capnp::server::ShutdownParams,
        _: server_capnp::server::ShutdownResults,
    ) -> Result<(), capnp::Error> {
        self.tx
            .send(())
            .map_err(|_| capnp::Error::failed("could not shutdown server.".to_string()))?;
        Ok(())
    }
}

pub struct WalletIpcInterface {
    state: WalletState,
}

impl WalletIpcInterface {
    pub fn new(state: WalletState) -> Self {
        Self { state }
    }
}

impl wallet_capnp::wallet::Server for WalletIpcInterface {
    async fn import_keys(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::ImportKeysParams,
        mut results: wallet_capnp::wallet::ImportKeysResults,
    ) -> Result<(), capnp::Error> {
        let scan_key_bytes = params.get()?.get_scan_key()?;
        let spend_key_bytes = params.get()?.get_spend_key()?;

        let scan_key = match ScanKey::from_slice(scan_key_bytes) {
            Ok(k) => k,
            Err(e) => {
                results.get().set_success(false);
                results.get().set_message(format!("invalid scan key: {e}"));
                return Ok(());
            }
        };

        let spend_key = match SpendKey::from_slice(spend_key_bytes) {
            Ok(k) => k,
            Err(e) => {
                results.get().set_success(false);
                results.get().set_message(format!("invalid spend key: {e}"));
                return Ok(());
            }
        };

        *self.state.scan_key.lock().unwrap() = Some(scan_key);
        *self.state.spend_key.lock().unwrap() = Some(spend_key);

        results.get().set_success(true);
        results.get().set_message("keys imported successfully");
        Ok(())
    }

    async fn get_balance(
        self: capnp::capability::Rc<Self>,
        _params: wallet_capnp::wallet::GetBalanceParams,
        mut results: wallet_capnp::wallet::GetBalanceResults,
    ) -> Result<(), capnp::Error> {
        let wallet = self.state.wallet.lock().unwrap();
        results.get().set_balance(wallet.balance());
        results.get().set_scan_height(wallet.scan_height);
        results.get().set_utxo_count(wallet.unspent_count() as u32);
        Ok(())
    }

    async fn get_history(
        self: capnp::capability::Rc<Self>,
        _params: wallet_capnp::wallet::GetHistoryParams,
        mut results: wallet_capnp::wallet::GetHistoryResults,
    ) -> Result<(), capnp::Error> {
        let wallet = self.state.wallet.lock().unwrap();
        let history = build_history(&wallet);

        if history.is_empty() {
            results.get().set_history("No transaction history.");
            return Ok(());
        }

        let mut lines = Vec::new();
        for entry in &history {
            match entry {
                HistoryEntry::Received {
                    outpoint,
                    amount,
                    block_height,
                } => {
                    lines.push(format!(
                        "Block {}: Received {} sats (outpoint: {:?})",
                        block_height, amount, outpoint
                    ));
                }
                HistoryEntry::Spent {
                    outpoint,
                    amount,
                    block_height,
                    ..
                } => {
                    lines.push(format!(
                        "Block {}: Spent {} sats (outpoint: {:?})",
                        block_height, amount, outpoint
                    ));
                }
            }
        }

        results.get().set_history(lines.join("\n"));
        Ok(())
    }
}
