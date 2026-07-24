mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;
use common::TestNode;

fn send(stream: &mut TcpStream, msg: NetworkMessage) {
    let raw = RawNetworkMessage::new(Network::Regtest.magic(), msg);
    let mut bytes = Vec::new();
    raw.consensus_encode(&mut bytes).unwrap();
    stream.write_all(&bytes).unwrap();
}

fn mock_version(node_addr: SocketAddr, my_addr: SocketAddr) -> NetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    NetworkMessage::Version(VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp,
        receiver: Address::new(&node_addr, ServiceFlags::NONE),
        sender: Address::new(&my_addr, ServiceFlags::NETWORK),
        nonce: 0x00dead_00beef_0000,
        user_agent: "/mock:0.1/".to_string(),
        start_height: 0,
        relay: false,
    })
}

#[test]
fn exits_when_shutdown_races_a_pending_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mock_addr = listener.local_addr().unwrap();

    let (connected_tx, connected_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let mock = thread::spawn(move || {
        let (mut stream, node_addr) = listener.accept().unwrap();
        let mut reader = stream.try_clone().unwrap();
        let _ = RawNetworkMessage::consensus_decode(&mut reader);
        connected_tx.send(node_addr).unwrap();

        release_rx.recv().unwrap();
        send(&mut stream, mock_version(node_addr, mock_addr));
        send(&mut stream, NetworkMessage::Verack);

        let mut buf = [0u8; 1024];
        while let Ok(n) = stream.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    });

    let mut node = TestNode::start_connected(mock_addr);
    let node_addr = connected_rx.recv_timeout(Duration::from_secs(15)).unwrap();
    println!("mock peer accepted node connection from {node_addr}, handshake pending");

    let out = node.cli(&["stop"]);
    assert!(
        out.status.success(),
        "cli stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    thread::sleep(Duration::from_secs(1));
    release_tx.send(()).unwrap();

    assert!(
        node.wait_for_exit(Duration::from_secs(20)),
        "node did not exit within 20s after shutdown raced a pending handshake"
    );

    drop(mock);
}
