use clap::Parser;
use kernel_node::kernel_util::DirnameExt;
use kernel_node::server_capnp::server;
use kernel_node::wallet_capnp::wallet;
use tokio::net::UnixStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const DEFAULT_DATA_DIR: &str = "~/.kernel-node/";

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Clone, clap::Args)]
struct Opts {
    /// Path to the data directory.
    #[arg(long, short)]
    datadir: Option<String>,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Commands {
    /// Echo a message to yourself.
    Echo(Echo),
    /// Terminate the server.
    Stop,
    /// Silent payment wallet commands.
    #[command(subcommand)]
    Wallet(WalletCommands),
}

#[derive(Debug, Clone, clap::Args)]
struct Echo {
    /// The message to echo.
    message: String,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum WalletCommands {
    /// Import scan and spend keys (hex-encoded).
    ImportKeys {
        /// 32-byte scan secret key in hex (64 hex chars).
        scan_key: String,
        /// 33-byte compressed spend public key in hex (66 hex chars).
        spend_key: String,
    },
    /// Show current wallet balance.
    Balance,
    /// Show transaction history.
    History,
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
        .collect()
}

fn main() {
    let cli = Args::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let datadir_path = cli.opts.datadir.unwrap_or(DEFAULT_DATA_DIR.data_dir());
    let sock_file = match &cli.commands {
        Commands::Wallet(_) => datadir_path + "/wallet.sock",
        _ => datadir_path + "/node.sock",
    };
    rt.block_on(tokio::task::LocalSet::new().run_until(async move {
        let stream = UnixStream::connect(sock_file)
            .await
            .expect("Could not connect to unix socket. Is `node` running?");
        let (reader, writer) = stream.into_split();
        let buf_reader = futures::io::BufReader::new(reader.compat());
        let buf_writer = futures::io::BufWriter::new(writer.compat_write());
        let network = capnp_rpc::twoparty::VatNetwork::new(
            buf_reader,
            buf_writer,
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            Default::default(),
        );
        let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);
        match cli.commands {
            Commands::Echo(echo_cmd) => {
                let client: server::Client =
                    rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(rpc_system);

                let mut echo_req = client.echo_request();
                println!("Sending... {}", echo_cmd.message);
                echo_req.get().set_msg(echo_cmd.message);
                let result = echo_req.send().promise.await.unwrap();
                let result = result
                    .get()
                    .unwrap()
                    .get_reply()
                    .unwrap()
                    .to_string()
                    .unwrap();
                println!("{result}");
            }
            Commands::Stop => {
                let client: server::Client =
                    rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(rpc_system);
                let shutdown_req = client.shutdown_request();
                shutdown_req.send().promise.await.unwrap();
                println!("Kernel node stopping...");
            }
            Commands::Wallet(wallet_cmd) => {
                let client: wallet::Client =
                    rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(rpc_system);

                match wallet_cmd {
                    WalletCommands::ImportKeys {
                        scan_key,
                        spend_key,
                    } => {
                        let scan_bytes = match hex_to_bytes(&scan_key) {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("Error: scan key: {e}");
                                return;
                            }
                        };
                        let spend_bytes = match hex_to_bytes(&spend_key) {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("Error: spend key: {e}");
                                return;
                            }
                        };

                        let mut req = client.import_keys_request();
                        req.get().set_scan_key(&scan_bytes);
                        req.get().set_spend_key(&spend_bytes);
                        let result = req.send().promise.await.unwrap();
                        let response = result.get().unwrap();
                        let success = response.get_success();
                        let message = response.get_message().unwrap().to_string().unwrap();
                        if success {
                            println!("OK: {message}");
                        } else {
                            eprintln!("Error: {message}");
                        }
                    }
                    WalletCommands::Balance => {
                        let req = client.get_balance_request();
                        let result = req.send().promise.await.unwrap();
                        let response = result.get().unwrap();
                        let balance = response.get_balance();
                        let scan_height = response.get_scan_height();
                        let utxo_count = response.get_utxo_count();
                        println!("Balance:     {} sats", balance);
                        println!("Scan height: {}", scan_height);
                        println!("UTXOs:       {}", utxo_count);
                    }
                    WalletCommands::History => {
                        let req = client.get_history_request();
                        let result = req.send().promise.await.unwrap();
                        let response = result.get().unwrap();
                        let history = response.get_history().unwrap().to_string().unwrap();
                        println!("{history}");
                    }
                }
            }
        }
    }))
}
