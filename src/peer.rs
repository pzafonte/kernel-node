use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    sync::{mpsc, Arc},
};

use bitcoin::{
    hashes::Hash,
    p2p::{
        address::AddrV2Message,
        message::NetworkMessage,
        message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory},
        Address, ServiceFlags,
    },
};
use bitcoin::{BlockHash, Network};
use bitcoinkernel::{
    core::BlockHashExt, BlockTreeEntry, ChainstateManager, Context, ProcessBlockHeaderResult,
};
use log::{debug, info, warn};
use p2p::{
    handshake::{ConnectionConfig, ProtocolVersion},
    net::{ConnectionExt, ConnectionReader, ConnectionWriter, TimeoutParams},
};

use crate::{
    ext::{CrateBlockExt, CrateHeaderExt},
    logging::Category,
};

const PROTOCOL_VERSION: ProtocolVersion = 70015;
const MAX_LOCATOR_HASHES: usize = 101;

pub struct NodeState {
    pub addr_tx: mpsc::Sender<Vec<AddrV2Message>>,
    pub block_tx: mpsc::SyncSender<bitcoinkernel::Block>,
    pub context: Arc<Context>,
    pub chainman: Arc<ChainstateManager>,
}

impl NodeState {
    pub fn is_on_active_chain(&self, block_hash: &bitcoin::BlockHash) -> bool {
        let hash = bitcoinkernel::BlockHash::from(block_hash.to_byte_array());
        match self.chainman.get_block_tree_entry(&hash) {
            Some(entry) => self.chainman.active_chain().contains(&entry),
            None => false,
        }
    }
}

/// State Machine for setting up a connection and getting blocks from a peer
///
/// ```text
///       [*]
///        │
/// AwaitingHeaders ◄──┐
///        │           │
///        ▼           │ unconnecting headers
///   AwaitingInv ─────┘
///       ▲ |
/// Block | | Inv / Headers
///       | ▼
///   AwaitingBlock
///       │ ▲
///       │ │
///       └─┘
///      Block
/// ```
#[derive(Default)]
pub enum PeerStateMachine {
    #[default]
    AwaitingHeaders,
    AwaitingInv,
    AwaitingBlock(AwaitingBlock),
}

pub struct AwaitingBlock {
    pub peer_inventory: HashSet<bitcoin::BlockHash>,
    pub block_buffer: HashMap<bitcoin::BlockHash /*prev */, bitcoinkernel::Block>,
}

fn build_block_locators(tip: BlockTreeEntry<'_>) -> Vec<BlockHash> {
    let height = tip.height();
    assert!(height >= 0);
    let mut locators = Vec::with_capacity(MAX_LOCATOR_HASHES);
    let mut entry = tip;
    let mut current_height = height as usize;
    let mut step: usize = 1;
    loop {
        let hash = BlockHash::from_byte_array(entry.block_hash().to_bytes());
        locators.push(hash);
        if current_height == 0 || locators.len() >= MAX_LOCATOR_HASHES {
            break;
        }
        if locators.len() > 10 {
            step *= 2;
        }
        let target = current_height.saturating_sub(step);
        while current_height > target {
            match entry.prev() {
                Some(prev) => {
                    entry = prev;
                    current_height -= 1;
                }
                None => break,
            }
        }
    }
    locators
}

fn create_getheaders_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    })
}

fn create_getblocks_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetBlocks(GetBlocksMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    })
}

fn create_getdata_message(block_hashes: &[bitcoin::BlockHash]) -> NetworkMessage {
    let inventory: Vec<Inventory> = block_hashes
        .iter()
        .map(|hash| Inventory::WitnessBlock(*hash))
        .collect();

    NetworkMessage::GetData(inventory)
}

pub fn process_message(
    state_machine: PeerStateMachine,
    event: NetworkMessage,
    node_state: &NodeState,
) -> (PeerStateMachine, Vec<NetworkMessage>) {
    // Always process the ping first as a special case.
    if let NetworkMessage::Ping(nonce) = event {
        info!(target: Category::NET, "Received ping, responding pong.");
        return (state_machine, vec![NetworkMessage::Pong(nonce)]);
    }

    if let NetworkMessage::AddrV2(payload) = event {
        info!(target: Category::NET, "Received {} net addresses", payload.len());
        // If the address manager has a full queue these net addresses should be dropped.
        let _ = node_state.addr_tx.send(payload);
        return (state_machine, vec![]);
    }

    match state_machine {
        PeerStateMachine::AwaitingHeaders => match event {
            NetworkMessage::Headers(headers) => {
                let msg_len = headers.len();
                for header in headers.into_iter() {
                    let result = node_state.chainman.process_block_header(&header.convert());
                    match result {
                        Ok(ProcessBlockHeaderResult::Valid) => {
                            debug!(target: Category::KERNEL, "Processed header: {}", header.time);
                            continue;
                        }
                        _ => {
                            warn!(target: Category::KERNEL, "Rejected header {}", header.block_hash());
                            break;
                        }
                    }
                }

                if msg_len != 2000 {
                    let locators = build_block_locators(node_state.chainman.active_chain().tip());
                    return (
                        PeerStateMachine::AwaitingInv,
                        vec![create_getblocks_message(locators)],
                    );
                }

                let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
                (
                    PeerStateMachine::AwaitingHeaders,
                    vec![create_getheaders_message(locators)],
                )
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingHeaders, vec![])
            }
        },
        PeerStateMachine::AwaitingInv => match event {
            NetworkMessage::Headers(headers) => {
                let mut announced = Vec::with_capacity(headers.len());
                for header in headers {
                    let block_hash = header.block_hash();
                    let valid = matches!(
                        node_state.chainman.process_block_header(&header.convert()),
                        Ok(ProcessBlockHeaderResult::Valid)
                    );
                    if !valid {
                        warn!(target: Category::KERNEL, "Rejected announced header {}", block_hash);
                        break;
                    }
                    announced.push(block_hash);
                }

                if announced.is_empty() {
                    let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
                    return (
                        PeerStateMachine::AwaitingHeaders,
                        vec![create_getheaders_message(locators)],
                    );
                }

                debug!(target: Category::NET, "Requesting {} announced blocks", announced.len());
                (
                    PeerStateMachine::AwaitingBlock(AwaitingBlock {
                        peer_inventory: announced.iter().copied().collect(),
                        block_buffer: HashMap::new(),
                    }),
                    vec![create_getdata_message(&announced)],
                )
            }
            NetworkMessage::Inv(inventory) => {
                debug!(target: Category::NET, "Received inventory with {} items", inventory.len());
                let block_hashes: Vec<bitcoin::BlockHash> = inventory
                    .iter()
                    .filter_map(|inv| match inv {
                        Inventory::Block(hash) => Some(*hash),
                        _ => None,
                    })
                    .collect();

                if !block_hashes.is_empty() {
                    debug!(target: Category::NET, "Requesting {} blocks", block_hashes.len());
                    (
                        PeerStateMachine::AwaitingBlock(AwaitingBlock {
                            peer_inventory: block_hashes.iter().cloned().collect(),
                            block_buffer: HashMap::new(),
                        }),
                        vec![create_getdata_message(&block_hashes)],
                    )
                } else {
                    (PeerStateMachine::AwaitingInv, vec![])
                }
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingInv, vec![])
            }
        },
        PeerStateMachine::AwaitingBlock(mut block_state) => match event {
            NetworkMessage::Block(block) => {
                let prev_blockhash = block.header.prev_blockhash;
                block_state.peer_inventory.remove(&block.block_hash());
                block_state
                    .block_buffer
                    .insert(prev_blockhash, block.convert());

                while let Some(prev) = block_state
                    .block_buffer
                    .keys()
                    .copied()
                    .find(|prev| node_state.is_on_active_chain(prev))
                {
                    let next_block = block_state
                        .block_buffer
                        .remove(&prev)
                        .expect("hash came from the buffer");
                    if let Err(err) = node_state.block_tx.send(next_block) {
                        debug!(target: Category::NODE, "Encountered error on block send: {}", err);
                        return (PeerStateMachine::AwaitingBlock(block_state), vec![]);
                    }
                }

                // All expected blocks have arrived. Flush anything left in the
                // buffer to the kernel and request the next batch. The leftovers
                // are a competing branch from a reorg.
                if block_state.peer_inventory.is_empty() {
                    let leftovers: Vec<_> =
                        block_state.block_buffer.drain().map(|(_, b)| b).collect();
                    for leftover in leftovers {
                        if let Err(err) = node_state.block_tx.send(leftover) {
                            debug!(target: Category::NODE, "Encountered error on block send: {}", err);
                            return (PeerStateMachine::AwaitingBlock(block_state), vec![]);
                        }
                    }
                    let locators = build_block_locators(node_state.chainman.active_chain().tip());
                    (
                        PeerStateMachine::AwaitingInv,
                        vec![create_getblocks_message(locators)],
                    )
                } else {
                    (PeerStateMachine::AwaitingBlock(block_state), vec![])
                }
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingBlock(block_state), vec![])
            }
        },
    }
}

pub struct BitcoinPeer {
    addr: Address,
    writer: Arc<ConnectionWriter>,
    reader: ConnectionReader,
    state_machine: PeerStateMachine,
}

impl fmt::Display for BitcoinPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.addr)
    }
}

impl BitcoinPeer {
    pub fn new(
        socket_addr: SocketAddr,
        network: Network,
        node_state: &NodeState,
    ) -> Result<Self, p2p::net::Error> {
        let height = node_state.chainman.active_chain().height();
        let conf = ConnectionConfig::new()
            .change_network(network)
            .our_height(height)
            .request_addr()
            .set_service_requirement(ServiceFlags::NETWORK)
            .offer_services(ServiceFlags::WITNESS)
            .user_agent("/kernel-node:0.1.0/".into());
        let (writer, reader, _) = conf.open_connection(socket_addr, TimeoutParams::new())?;

        let addr = Address::new(&socket_addr, ServiceFlags::WITNESS);
        info!(target: Category::NET, "Connected to {:?}", addr);
        let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
        debug!(target: Category::NET, "Sending headers message...");
        writer.send_message(create_getheaders_message(locators))?;
        let peer = BitcoinPeer {
            addr,
            writer: Arc::new(writer),
            reader,
            state_machine: PeerStateMachine::AwaitingHeaders,
        };
        Ok(peer)
    }

    pub fn writer(&self) -> Arc<ConnectionWriter> {
        Arc::clone(&self.writer)
    }

    fn receive_message(&mut self) -> Result<NetworkMessage, p2p::net::Error> {
        Ok(self
            .reader
            .read_message()?
            .expect("v1 only supported currently"))
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &NodeState,
    ) -> Result<(), p2p::net::Error> {
        let msg = self.receive_message()?;
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) = process_message(old_state, msg, node_state);
        self.state_machine = peer_state_machine;
        for message in messages.drain(..) {
            self.writer.send_message(message)?
        }
        Ok(())
    }
}
