#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use corepc_node::{Conf, Node, P2P};
use kernel_node::server_capnp::server;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const TIP_POLL_INTERVAL: Duration = Duration::from_millis(200);

const CLOSED_PEER: &str = "127.0.0.1:1";

pub fn start_bitcoind() -> Node {
    let exe = corepc_node::exe_path()
        .expect("resolve bitcoind: downloaded build, or BITCOIND_EXE, or bitcoind on PATH");
    let mut conf = Conf::default();
    conf.p2p = P2P::Yes;
    Node::with_conf(exe, &conf).unwrap()
}

async fn connect(socket_path: &Path) -> server::Client {
    let stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
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
    let client: server::Client = rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
    tokio::task::spawn_local(rpc_system);
    client
}

pub struct TestNode {
    process: Child,
    datadir: PathBuf,
    _tempdir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
}

impl TestNode {
    pub fn start() -> Self {
        Self::start_connected(CLOSED_PEER)
    }

    pub fn start_connected(peer: impl std::fmt::Display) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let datadir = tempdir.path().canonicalize().unwrap();
        let process = Command::new(env!("CARGO_BIN_EXE_node"))
            .arg("--network")
            .arg("regtest")
            .arg("--datadir")
            .arg(&datadir)
            .arg("--connect")
            .arg(peer.to_string())
            .spawn()
            .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let node = Self {
            process,
            datadir,
            _tempdir: tempdir,
            rt,
        };
        node.wait_until_ready();
        node
    }

    pub fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("--datadir")
            .arg(&self.datadir)
            .args(args)
            .output()
            .unwrap()
    }

    pub fn tip(&self) -> (u32, bitcoin::BlockHash) {
        let socket = self.socket_path();
        self.rt
            .block_on(tokio::task::LocalSet::new().run_until(async move {
                let client = connect(&socket).await;
                let chain = client
                    .make_chain_request()
                    .send()
                    .promise
                    .await
                    .unwrap()
                    .get()
                    .unwrap()
                    .get_chain()
                    .unwrap();
                let response = chain.get_tip_request().send().promise.await.unwrap();
                let reply = response.get().unwrap();
                let height = reply.get_height();
                let hash = reply
                    .get_hash()
                    .unwrap()
                    .to_string()
                    .unwrap()
                    .parse::<bitcoin::BlockHash>()
                    .unwrap();
                (height, hash)
            }))
    }

    pub fn wait_for_tip(&self, height: u64, hash: bitcoin::BlockHash, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let (h, block_hash) = self.tip();
            if u64::from(h) == height && block_hash == hash {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "node did not reach tip {height} within {timeout:?} (node at {h})"
            );
            std::thread::sleep(TIP_POLL_INTERVAL);
        }
    }

    pub fn stop(mut self) {
        let out = self.cli(&["stop"]);
        assert!(
            out.status.success(),
            "cli stop failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stop_started = Instant::now();
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if self.process.try_wait().unwrap().is_some() {
                eprintln!("DBG stop: node exited in {:?}", stop_started.elapsed());
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not exit within {STOP_TIMEOUT:?} after stop");
    }

    fn socket_path(&self) -> PathBuf {
        self.datadir.join("node.sock")
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if Path::new(&self.socket_path()).exists() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not create control socket within {READY_TIMEOUT:?}");
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
