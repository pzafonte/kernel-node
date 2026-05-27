use ::silentpayments::{
    receiving::{Label, Receiver},
    utils::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input},
};
use bitcoin::consensus::encode;
use bitcoin::secp256k1::{self, Scalar, SecretKey, XOnlyPublicKey};
use bitcoin::{OutPoint, Script, Transaction};
use bitcoinkernel::prelude::{
    BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt, TransactionExt, TransactionSpentOutputsExt,
    TxOutExt,
};

use crate::silentpayments::wallet::Coin;

pub struct InputData {
    pub script_sig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub prevout_script: Vec<u8>,
    pub txid: String,
    pub vout: u32,
}

pub fn scan_transaction(
    receiver: &Receiver,
    b_scan: &SecretKey,
    inputs: &[InputData],
    tx: &Transaction,
) -> Vec<(usize, Scalar, Option<Label>)> {
    let mut input_pub_keys = Vec::new();
    let mut outpoints = Vec::new();
    for input in inputs {
        if let Ok(Some(pk)) =
            get_pubkey_from_input(&input.script_sig, &input.witness, &input.prevout_script)
        {
            input_pub_keys.push(pk);
            outpoints.push((input.txid.clone(), input.vout));
        }
    }

    if input_pub_keys.is_empty() {
        return vec![];
    }

    // Silent payments always produce taproot outputs — skip transactions without any.
    let taproot_outputs: Vec<(usize, XOnlyPublicKey)> = tx
        .output
        .iter()
        .enumerate()
        .filter_map(|(i, out)| {
            if out.script_pubkey.is_p2tr() {
                XOnlyPublicKey::from_slice(&out.script_pubkey.as_bytes()[2..])
                    .ok()
                    .map(|pk| (i, pk))
            } else {
                None
            }
        })
        .collect();

    if taproot_outputs.is_empty() {
        return vec![];
    }

    let pubkey_refs: Vec<&secp256k1::PublicKey> = input_pub_keys.iter().collect();
    let tweak_data = match calculate_tweak_data(&pubkey_refs, &outpoints) {
        Ok(td) => td,
        Err(_) => return vec![],
    };
    let shared_secret = calculate_ecdh_shared_secret(&tweak_data, b_scan);

    let xonly_outputs: Vec<XOnlyPublicKey> = taproot_outputs.iter().map(|(_, pk)| *pk).collect();
    let found = match receiver.scan_transaction(&shared_secret, xonly_outputs) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let mut result = Vec::new();
    for (label, pubkey_map) in found.iter() {
        for (pk, tweak) in pubkey_map {
            if let Some((idx, _)) = taproot_outputs.iter().find(|(_, o)| o == pk) {
                result.push((*idx, *tweak, label.clone()));
            }
        }
    }
    result
}

pub(crate) fn scan_block_inner(
    receiver: &Receiver,
    b_scan: &SecretKey,
    kernel_block: &bitcoinkernel::Block,
    spent_outputs: bitcoinkernel::BlockSpentOutputs,
    block_height: u32,
) -> Vec<(OutPoint, Coin)> {
    let mut found: Vec<(OutPoint, Coin)> = Vec::new();

    // Skip coinbase; spent_outputs[i] maps to kernel_block.transactions().skip(1)[i].
    for (kernel_tx, tx_spent) in kernel_block
        .transactions()
        .skip(1)
        .zip(spent_outputs.iter())
    {
        let has_p2tr = kernel_tx.outputs().any(|out| {
            let bytes = out.script_pubkey().to_bytes();
            Script::from_bytes(&bytes).is_p2tr()
        });
        if !has_p2tr {
            continue;
        }

        let tx_bytes = kernel_tx
            .consensus_encode()
            .expect("kernel tx serialization");
        let btc_tx: Transaction =
            encode::deserialize(&tx_bytes).expect("kernel tx deserialization");

        let mut inputs = Vec::with_capacity(btc_tx.input.len());
        for (input_idx, btc_input) in btc_tx.input.iter().enumerate() {
            let coin = tx_spent
                .coin(input_idx)
                .expect("input/spent-output count mismatch");
            inputs.push(InputData {
                script_sig: btc_input.script_sig.as_bytes().to_vec(),
                witness: btc_input.witness.iter().map(|item| item.to_vec()).collect(),
                prevout_script: coin.output().script_pubkey().to_bytes(),
                txid: btc_input.previous_output.txid.to_string(),
                vout: btc_input.previous_output.vout,
            });
        }

        let txid = btc_tx.compute_txid();
        for (output_index, tweak, label) in scan_transaction(receiver, b_scan, &inputs, &btc_tx) {
            if let Some(out) = btc_tx.output.get(output_index) {
                let outpoint = OutPoint {
                    txid,
                    vout: output_index as u32,
                };
                found.push((
                    outpoint,
                    Coin {
                        value: out.value,
                        script_pubkey: out.script_pubkey.clone(),
                        tweak,
                        label: label.map(|l| l.into_inner()),
                        block_height,
                        spent_by: None,
                    },
                ));
            }
        }
    }
    found
}
