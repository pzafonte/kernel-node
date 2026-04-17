use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex, Once,
    },
    thread::{self, available_parallelism},
    time::{Duration, Instant},
};

use bitcoin::{
    block::Unchecked, consensus::encode::deserialize, secp256k1::Secp256k1, BlockHash, Network,
    TestnetVersion,
};
use bitcoinkernel::{
    core::BlockHashExt,
    prelude::{
        BlockSpentOutputsExt, BlockValidationStateExt, CoinExt, ScriptPubkeyExt,
        TransactionSpentOutputsExt, TxOutExt,
    },
    ChainType, ChainstateManagerBuilder, Context, ContextBuilder, Log, Logger,
    SynchronizationState, ValidationMode,
};
use kernel_node::{
    daemonize::Daemonize,
    ipc::{IpcInterface, WalletIpcInterface, WalletState},
    kernel_util::{ChainExt, DirnameExt},
    peer::{BitcoinPeer, NodeState, TipState},
    server_capnp::server,
    silentpayments::{scan_block, InputData, OutputData, TransactionData},
    wallet_capnp::wallet,
};
use log::{debug, error, info, warn};
use p2p::{
    dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS},
    p2p_message_types::{address::AddrV2, message::AddrV2Payload, NetworkExt, ServiceFlags},
};
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

const DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

const STALE_BLOCK_DURATION: Duration = Duration::from_secs(60 * 20);

configure_me::include_config!();

fn create_context(
    chain_type: ChainType,
    shutdown_tx: mpsc::Sender<()>,
    tip_state: &Arc<Mutex<TipState>>,
) -> Arc<Context> {
    let shutdown_triggered = Arc::new(AtomicBool::new(false));
    let shutdown_triggered_clone = Arc::clone(&shutdown_triggered);
    let shutdown_tx_clone = shutdown_tx.clone();
    let tip_state_clone = tip_state.clone();
    Arc::new(ContextBuilder::new()
        .chain_type(chain_type)
        .with_block_tip_notification(|state, hash: bitcoinkernel::BlockHash, _| {
                let hash = BlockHash::from_byte_array(hash.into());
                match state {
                    SynchronizationState::InitDownload => debug!("Received new block tip {} during IBD.", hash),
                    SynchronizationState::PostInit => info!("Received new block {}", hash),
                    SynchronizationState::InitReindex => debug!("Moved new block tip {} during reindex.", hash),
                };
        })
        .with_header_tip_notification(|state, height, timestamp, presync| {
                match state {
                    SynchronizationState::InitDownload => debug!("Received new header tip during IBD at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::PostInit => info!("Received new header tip at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::InitReindex => debug!("Moved to new header tip during reindex at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                }
        })
        .with_progress_notification(|title, progress, resume_possible| {
                warn!("Made progress {}: {}. Can resume: {}", title, progress, resume_possible)
        })
        .with_warning_set_notification(|_warning, _message| {})
        .with_warning_unset_notification(|_warning| {})
        .with_flush_error_notification(move |message| {
                if !shutdown_triggered.swap(true, Ordering::SeqCst) {
                    shutdown_tx.send(()).expect("failed to send shutdown signal");
                }
                error!("Fatal flush error encountered: {}", message);
        })
        .with_fatal_error_notification(move |message| {
                error!("Fatal error encountered: {}", message);
                if !shutdown_triggered_clone.swap(true, Ordering::SeqCst) {
                    shutdown_tx_clone.send(()).expect("failed to send shutdown signal");
                }
        })
        // .with_block_checked_validation(setup_validation_interface(tip_state))
        .with_block_checked_validation(move |block: bitcoinkernel::Block, state: bitcoinkernel::BlockValidationStateRef<'_>| {
            match state.mode() {
                ValidationMode::Valid => {
                    let hash = bitcoin::BlockHash::from_byte_array(block.hash().into());
                    log::debug!("Validation interface: Successfully checked block: {}", hash);
                    tip_state_clone.lock().unwrap().block_hash = hash;
                }
                _ => error!("Received an invalid block!"),
            }
        })
        .build()
        .unwrap())
}

struct KernelLog {}

impl Log for KernelLog {
    fn log(&self, message: &str) {
        log::info!(
            target: "bitcoinkernel", 
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    }
}

static START: Once = Once::new();
static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

fn setup_logging() {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    builder.init();

    unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(KernelLog {}).unwrap()) };
}

// fn setup_validation_interface(
//     tip_state: &Arc<Mutex<TipState>>,
// ) -> Box<ValidationInterfaceCallbacks> {
//     let tip_state_clone = Arc::clone(&tip_state);
//     Box::new(ValidationInterfaceCallbacks {
//         block_checked: Box::new(move |block, mode, _result| match mode {
//             ValidationMode::Valid => {
//                 let hash = bitcoin::BlockHash::from_byte_array(block.get_hash().hash);
//                 log::debug!("Validation interface: Successfully checked block: {}", hash);
//                 tip_state_clone.lock().unwrap().block_hash = hash;
//             }
//             _ => error!("Received an invalid block!"),
//         }),
//     })
// }

fn resolve_seeds(network: Network) -> Vec<IpAddr> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let format_hostname = |host: &str| format!("{host}:53");
    let seeds: Vec<String> = match network {
        Network::Bitcoin => BITCOIN_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Signet => SIGNET_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Testnet(TestnetVersion::V3) => {
            TESTNET3_SEEDS.into_iter().map(format_hostname).collect()
        }
        Network::Testnet(TestnetVersion::V4) => {
            TESTNET4_SEEDS.into_iter().map(format_hostname).collect()
        }
        Network::Regtest => Vec::new(),
        _ => panic!("unknown network."),
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

struct TxScanData {
    txid: [u8; 32],
    prevout_scripts: Vec<Vec<u8>>,
    script_sigs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<Vec<u8>>>,
    outpoints: Vec<[u8; 36]>,
    outputs: Vec<(u32, i64, Vec<u8>)>,
}

fn scan_kernel_block(
    chainman: &bitcoinkernel::ChainstateManager,
    kernel_block: &bitcoinkernel::Block,
    wallet_state: &WalletState,
) {
    let scan_key = *wallet_state.scan_key.lock().unwrap();
    let spend_key = *wallet_state.spend_key.lock().unwrap();
    let (scan_key, spend_key) = match (scan_key, spend_key) {
        (Some(s), Some(sp)) => (s, sp),
        _ => return,
    };

    let raw = match kernel_block.consensus_encode() {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to encode block for scanning: {e}");
            return;
        }
    };
    let btc_block: bitcoin::Block<Unchecked> = match deserialize(&raw) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to decode block for scanning: {e}");
            return;
        }
    };

    let block_hash = kernel_block.hash();
    let entry = match chainman.get_block_tree_entry(&block_hash) {
        Some(e) => e,
        None => {
            warn!("Scanned block not found in block tree");
            return;
        }
    };
    let block_height = entry.height() as u32;
    let spent_outputs = match chainman.read_spent_outputs(&entry) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to read undo data for scanning: {e}");
            return;
        }
    };

    let (_, txs) = btc_block.into_parts();
    let mut input_outpoints: Vec<([u8; 32], [u8; 32], u32)> = Vec::new();
    let mut tx_data: Vec<TxScanData> = Vec::with_capacity(spent_outputs.count());

    for (i, tx_spent) in spent_outputs.iter().enumerate() {
        let btc_tx_idx = i + 1;
        if btc_tx_idx >= txs.len() {
            warn!("Undo data has more entries than block transactions");
            break;
        }
        let btc_tx = &txs[btc_tx_idx];
        let txid = btc_tx.compute_txid().to_byte_array();

        let mut prevout_scripts = Vec::new();
        let mut script_sigs = Vec::new();
        let mut witnesses: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut outpoints = Vec::new();

        for (j, coin) in tx_spent.coins().enumerate() {
            if j >= btc_tx.inputs.len() {
                break;
            }
            let inp = &btc_tx.inputs[j];
            let prev_txid = inp.previous_output.txid.to_byte_array();
            let prev_vout = inp.previous_output.vout;

            let mut op = [0u8; 36];
            op[..32].copy_from_slice(&prev_txid);
            op[32..].copy_from_slice(&prev_vout.to_le_bytes());

            input_outpoints.push((txid, prev_txid, prev_vout));
            prevout_scripts.push(coin.output().script_pubkey().to_bytes().to_vec());
            script_sigs.push(inp.script_sig.as_bytes().to_vec());
            witnesses.push(inp.witness.iter().map(|w: &[u8]| w.to_vec()).collect());
            outpoints.push(op);
        }

        let outputs = btc_tx
            .outputs
            .iter()
            .enumerate()
            .map(|(vout, out)| {
                (
                    vout as u32,
                    out.value.to_sat() as i64,
                    out.script_pubkey.as_bytes().to_vec(),
                )
            })
            .collect();

        tx_data.push(TxScanData {
            txid,
            prevout_scripts,
            script_sigs,
            witnesses,
            outpoints,
            outputs,
        });
    }

    let secp = Secp256k1::verification_only();
    let transactions: Vec<TransactionData<'_>> = tx_data
        .iter()
        .map(|td| {
            let inputs = td
                .prevout_scripts
                .iter()
                .enumerate()
                .map(|(j, prevout)| InputData {
                    prevout_script: prevout.as_slice(),
                    script_sig: td.script_sigs[j].as_slice(),
                    witness: td.witnesses[j].iter().map(|w| w.as_slice()).collect(),
                    outpoint: td.outpoints[j],
                })
                .collect();
            let outputs = td
                .outputs
                .iter()
                .map(|(vout, value, script)| OutputData {
                    vout: *vout,
                    value: *value,
                    script_pubkey: script.as_slice(),
                })
                .collect();
            TransactionData {
                txid: td.txid,
                inputs,
                outputs,
            }
        })
        .collect();

    let payments = scan_block(&secp, &scan_key, &spend_key, &transactions);

    let mut wallet = wallet_state.wallet.lock().unwrap();
    wallet.check_for_spends(&input_outpoints, block_height);
    wallet.process_found_payments(&payments, block_height);
}

fn run(
    network: Network,
    connect: Option<SocketAddr>,
    mut node_state: NodeState,
    shutdown_rx: mpsc::Receiver<()>,
    addr_rx: mpsc::Receiver<AddrV2Payload>,
    block_rx: mpsc::Receiver<bitcoinkernel::Block>,
    wallet_state: WalletState,
) -> std::io::Result<()> {
    let mut table = addrman::Table::<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>::new();
    match connect {
        Some(connect) => {
            let record = match connect.ip() {
                IpAddr::V4(ipv4) => addrman::Record::new(
                    AddrV2::Ipv4(ipv4),
                    connect.port(),
                    ServiceFlags::NETWORK,
                    &DNS_RESOLVER,
                ),
                IpAddr::V6(ipv6) => addrman::Record::new(
                    AddrV2::Ipv6(ipv6),
                    connect.port(),
                    ServiceFlags::NETWORK,
                    &DNS_RESOLVER,
                ),
            };
            table.add(&record);
        }
        None => {
            let addresses = resolve_seeds(network);
            info!("{} addresses resolved from the dns seeds", addresses.len());
            for addr in &addresses {
                let record = match addr {
                    IpAddr::V4(ipv4) => addrman::Record::new(
                        AddrV2::Ipv4(*ipv4),
                        network.default_p2p_port(),
                        ServiceFlags::NETWORK,
                        &DNS_RESOLVER,
                    ),
                    IpAddr::V6(ipv6) => addrman::Record::new(
                        AddrV2::Ipv6(*ipv6),
                        network.default_p2p_port(),
                        ServiceFlags::NETWORK,
                        &DNS_RESOLVER,
                    ),
                };
                table.add(&record);
            }
        }
    };

    let chainman = Arc::clone(&node_state.chainman);
    let context = Arc::clone(&node_state.context);
    let addrman = Arc::new(Mutex::new(table));

    let running = Arc::new(AtomicBool::new(true));
    let running_addr = running.clone();
    let running_peer = running.clone();
    let running_block = running.clone();

    let peer_source = Arc::clone(&addrman);
    let kill = Arc::new(Mutex::new(None));
    let writer = Arc::clone(&kill);
    let stale_block_kill = Arc::clone(&kill);

    let peer_processing_handler = thread::spawn(move || {
        info!("Starting net processing thread.");
        while running_peer.load(Ordering::SeqCst) {
            let addr_lock = peer_source.lock().unwrap();
            let (address, port) = addr_lock.select().unwrap().network_addr();
            let peer = match address {
                AddrV2::Ipv4(ipv4) => BitcoinPeer::new(
                    SocketAddr::V4(SocketAddrV4::new(ipv4, port)),
                    network,
                    &mut node_state,
                ),
                AddrV2::Ipv6(ipv6) => {
                    let socket_adrr = (ipv6, port).into();
                    BitcoinPeer::new(socket_adrr, network, &mut node_state)
                }
                _ => continue,
            };
            let mut peer = match peer {
                Ok(connection) => {
                    let mut writer_lock = writer.lock().unwrap();
                    *writer_lock = Some(connection.writer());
                    connection
                }
                Err(e) => {
                    error!("Could not connect: {e}");
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            loop {
                if let Err(e) = peer.receive_and_process_message(&mut node_state) {
                    match e {
                        p2p::net::Error::Io(io) => {
                            if io.kind() != std::io::ErrorKind::UnexpectedEof {
                                error!("Unexpected I/O error: {}", io);
                            }
                        }
                        e => error!("Error processing message: {e}"),
                    }
                    break;
                }
            }
        }
        info!("Stopping net processing thread.");
    });

    let addr_processing_handler = thread::spawn(move || {
        info!("Starting addr processing thread.");
        while running_addr.load(Ordering::SeqCst) {
            match addr_rx.recv() {
                Ok(payload) => {
                    let mut addr_lock = addrman.lock().unwrap();
                    for address in payload.0 {
                        let record = addrman::Record::new(
                            address.addr,
                            address.port,
                            address.services,
                            &DNS_RESOLVER,
                        );
                        addr_lock.add(&record);
                    }
                }
                Err(_) => break,
            }
        }
        info!("Stopping addr processing thread.");
    });

    let wallet_state_block = wallet_state.clone();

    let block_processing_handler = thread::spawn(move || {
        info!("Starting block processing thread.");
        let mut last_block = Instant::now();
        while running_block.load(Ordering::SeqCst) {
            match block_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(block) => {
                    debug!("Validating block.");
                    last_block = Instant::now();
                    let result = chainman.process_block(&block);
                    if result.is_new_block() {
                        scan_kernel_block(&chainman, &block, &wallet_state_block);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if last_block.elapsed() > STALE_BLOCK_DURATION {
                        last_block = Instant::now();
                        info!("Potential stale block. Finding a new peer.");
                        let mut peer_lock = stale_block_kill.lock().unwrap();
                        if let Some(conn) = peer_lock.deref_mut() {
                            let _ = conn.shutdown();
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        info!("Stopping block processing thread.");
    });

    if let Ok(()) = shutdown_rx.recv() {
        context.interrupt().unwrap();
        let mut peer_lock = kill.lock().unwrap();
        if let Some(conn) = peer_lock.deref_mut() {
            conn.shutdown().unwrap()
        }
        info!("Received shutdown signal, shutting down...");
        running.store(false, Ordering::SeqCst);
    }

    addr_processing_handler.join().unwrap();
    peer_processing_handler.join().unwrap();
    block_processing_handler.join().unwrap();

    info!("exiting.");
    Ok(())
}

fn main() {
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    START.call_once(|| {
        setup_logging();
    });
    if config.daemon {
        let daemonize = Daemonize::new(config.datadir.data_dir());
        info!("Kernel node starting...");
        daemonize.fork().unwrap();
    }

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let ipc_shutdown = shutdown_tx.clone();

    let tip_state = Arc::new(Mutex::new(TipState::default()));

    let network = config.network.parse::<Network>().expect("invalid network");
    let context = create_context(network.chain_type(), shutdown_tx.clone(), &tip_state);

    let data_dir = config.datadir.data_dir();
    let blocks_dir = data_dir.clone() + "/blocks";
    let chainman_builder = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
        .unwrap()
        .worker_threads(
            ((available_parallelism().unwrap().get() / 2) + 1)
                .try_into()
                .unwrap(),
        );
    let chainman = Arc::new(chainman_builder.build().unwrap());

    let (block_tx, block_rx) = mpsc::sync_channel(1);
    let (addr_tx, addr_rx) = mpsc::channel();

    let node_state = NodeState {
        addr_tx,
        block_tx,
        tip_state,
        chainman,
        context: Arc::clone(&context),
    };

    if let Err(err) = node_state.chainman.import_blocks() {
        error!("Error importing blocks: {}", err);
        return;
    }

    let tip_index = node_state.chainman.active_chain().tip();
    let hash = tip_index.block_hash();
    node_state.set_tip_state(BlockHash::from_byte_array(hash.to_bytes()));

    info!("Bitcoin kernel initialized");

    let connect = config
        .connect
        .map(|sock| sock.parse::<SocketAddr>().unwrap());

    if shutdown_rx.try_recv().is_ok() {
        info!("Shutting down!");
        return;
    }

    let wallet_state = WalletState::new();
    let wallet_state_ipc = wallet_state.clone();

    let sock_file = data_dir.clone() + "/node.sock";
    let wallet_sock_file = data_dir + "/wallet.sock";

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            tokio::task::LocalSet::new()
                .run_until(async move {
                    let _ = std::fs::remove_file(&sock_file);
                    let _ = std::fs::remove_file(&wallet_sock_file);
                    info!("Listening for incoming IPC requests");
                    let unix_socket = UnixListener::bind(&sock_file).unwrap();
                    let wallet_socket = UnixListener::bind(wallet_sock_file).unwrap();

                    tokio::task::spawn_local(async move {
                        loop {
                            let Ok((stream, _)) = wallet_socket.accept().await else {
                                return;
                            };
                            let (reader, writer) = stream.into_split();
                            let buf_reader = futures::io::BufReader::new(reader.compat());
                            let buf_writer = futures::io::BufWriter::new(writer.compat_write());
                            let network = capnp_rpc::twoparty::VatNetwork::new(
                                buf_reader,
                                buf_writer,
                                capnp_rpc::rpc_twoparty_capnp::Side::Server,
                                Default::default(),
                            );
                            let client: wallet::Client = capnp_rpc::new_client(
                                WalletIpcInterface::new(wallet_state_ipc.clone()),
                            );
                            let rpc_system =
                                capnp_rpc::RpcSystem::new(Box::new(network), Some(client.client));
                            tokio::task::spawn_local(rpc_system);
                        }
                    });

                    loop {
                        let stream = tokio::select! {
                            unix_bind_res = unix_socket.accept() => {
                                unix_bind_res.unwrap().0
                            }
                            _ctrl_c = tokio::signal::ctrl_c() => {
                                info!("Received shutdown signal");
                                shutdown_tx.clone().send(()).unwrap();
                                return;
                            }
                        };
                        info!("Handling inbound IPC call");
                        let (reader, writer) = stream.into_split();
                        let buf_reader = futures::io::BufReader::new(reader.compat());
                        let buf_writer = futures::io::BufWriter::new(writer.compat_write());
                        let network = capnp_rpc::twoparty::VatNetwork::new(
                            buf_reader,
                            buf_writer,
                            capnp_rpc::rpc_twoparty_capnp::Side::Server,
                            Default::default(),
                        );
                        let client: server::Client =
                            capnp_rpc::new_client(IpcInterface::new(ipc_shutdown.clone()));
                        let rpc_system =
                            capnp_rpc::RpcSystem::new(Box::new(network), Some(client.client));
                        tokio::task::spawn_local(rpc_system);
                    }
                })
                .await;
        })
    });

    run(
        network,
        connect,
        node_state,
        shutdown_rx,
        addr_rx,
        block_rx,
        wallet_state,
    )
    .unwrap()
}
