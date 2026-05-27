use std::sync::{mpsc, Arc, Mutex};

use crate::{server_capnp, wallet_capnp, WalletState};
use bitcoin::consensus::Decodable;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::Transaction;

#[derive(Debug)]
pub struct IpcInterface {
    tx: mpsc::Sender<()>,
    broadcast_tx: mpsc::SyncSender<Transaction>,
    wallet_state: Arc<Mutex<WalletState>>,
}

impl IpcInterface {
    pub fn new(
        tx: mpsc::Sender<()>,
        broadcast_tx: mpsc::SyncSender<Transaction>,
        wallet_state: Arc<Mutex<WalletState>>,
    ) -> Self {
        Self {
            tx,
            broadcast_tx,
            wallet_state,
        }
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

    async fn make_wallet(
        self: capnp::capability::Rc<Self>,
        _: server_capnp::server::MakeWalletParams,
        mut results: server_capnp::server::MakeWalletResults,
    ) -> Result<(), capnp::Error> {
        let client: wallet_capnp::wallet::Client = capnp_rpc::new_client(WalletIpcInterface::new(
            self.wallet_state.clone(),
            self.broadcast_tx.clone(),
        ));
        results.get().set_wallet(client);
        Ok(())
    }
}

pub struct WalletIpcInterface {
    wallet_state: Arc<Mutex<WalletState>>,
    broadcast_tx: mpsc::SyncSender<Transaction>,
}

impl WalletIpcInterface {
    pub fn new(
        wallet_state: Arc<Mutex<WalletState>>,
        broadcast_tx: mpsc::SyncSender<Transaction>,
    ) -> Self {
        Self {
            wallet_state,
            broadcast_tx,
        }
    }
}

impl wallet_capnp::wallet::Server for WalletIpcInterface {
    async fn import_keys(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::ImportKeysParams,
        mut results: wallet_capnp::wallet::ImportKeysResults,
    ) -> Result<(), capnp::Error> {
        let p = params.get()?;
        let scan_bytes = p.get_scan_key()?;
        let spend_bytes = p.get_spend_key()?;

        let scan_key = SecretKey::from_slice(scan_bytes)
            .map_err(|e| capnp::Error::failed(format!("invalid scan key: {e}")))?;
        let spend_xonly = XOnlyPublicKey::from_slice(spend_bytes)
            .map_err(|e| capnp::Error::failed(format!("invalid spend key: {e}")))?;

        let mut wallet_state = self.wallet_state.lock().unwrap();
        wallet_state
            .wallet
            .import_keys(scan_key, spend_xonly)
            .map_err(|e| capnp::Error::failed(format!("invalid key pair: {e}")))?;
        wallet_state.ensure_store();

        results.get().set_ok(true);
        results.get().set_message("keys imported");
        Ok(())
    }

    async fn get_balance(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::GetBalanceParams,
        mut results: wallet_capnp::wallet::GetBalanceResults,
    ) -> Result<(), capnp::Error> {
        let wallet_state = self.wallet_state.lock().unwrap();
        let balance = wallet_state.wallet.balance();
        let scan_height = wallet_state.wallet.scan_height;
        let utxo_count = wallet_state.wallet.utxo_count() as u32;
        drop(wallet_state);

        let mut r = results.get();
        r.set_sats(balance.to_sat());
        r.set_scan_height(scan_height);
        r.set_utxo_count(utxo_count);
        Ok(())
    }

    async fn get_history(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::GetHistoryParams,
        mut results: wallet_capnp::wallet::GetHistoryResults,
    ) -> Result<(), capnp::Error> {
        let wallet_state = self.wallet_state.lock().unwrap();
        let history = wallet_state.wallet.history();
        drop(wallet_state);

        let text = history
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        results.get().set_entries(&text);
        Ok(())
    }

    async fn receive(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::ReceiveParams,
        mut results: wallet_capnp::wallet::ReceiveResults,
    ) -> Result<(), capnp::Error> {
        let wallet_state = self.wallet_state.lock().unwrap();
        let address = wallet_state
            .wallet
            .receive_address()
            .ok_or_else(|| capnp::Error::failed("no keys imported".to_string()))?;
        drop(wallet_state);

        results.get().set_address(&address);
        Ok(())
    }

    async fn broadcast_raw_tx(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::BroadcastRawTxParams,
        mut results: wallet_capnp::wallet::BroadcastRawTxResults,
    ) -> Result<(), capnp::Error> {
        let mut raw = params.get()?.get_tx()?;
        let tx = Transaction::consensus_decode(&mut raw)
            .map_err(|e| capnp::Error::failed(format!("invalid transaction: {e}")))?;
        let txid = tx.compute_txid().to_string();
        self.broadcast_tx
            .try_send(tx)
            .map_err(|e| capnp::Error::failed(format!("broadcast unavailable: {e}")))?;
        results.get().set_txid(&txid);
        Ok(())
    }
}
