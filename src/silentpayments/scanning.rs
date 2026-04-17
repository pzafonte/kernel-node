use bitcoin::hashes::hash160;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Verification, XOnlyPublicKey};

use super::{compute_input_hash, compute_shared_secret, derive_output_pubkey, ScanKey, SpendKey};

fn is_p2wpkh(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == 0x00 && script[1] == 0x14
}

fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

// Key-path: 1 item (Schnorr sig). Annex (0x50 prefix on last item) doesn't
// count toward the stack depth. Script-path spends are not eligible.
fn is_p2tr_key_path(witness: &[&[u8]]) -> bool {
    if witness.is_empty() {
        return false;
    }
    let has_annex = witness.len() >= 2 && witness.last().is_some_and(|w| w.first() == Some(&0x50));
    let effective_len = if has_annex {
        witness.len() - 1
    } else {
        witness.len()
    };
    effective_len == 1
}

// Backward 33-byte sliding-window hash160 scan — handles malleated scriptSigs
// without opcode parsing, matching the BIP-352 reference implementation.
fn extract_pubkey_from_scriptsig(script_sig: &[u8], expected_hash: &[u8; 20]) -> Option<PublicKey> {
    if script_sig.len() < 33 {
        return None;
    }
    let start = script_sig.len() - 33;
    for i in (0..=start).rev() {
        let candidate = &script_sig[i..i + 33];
        let h = hash160::Hash::hash(candidate);
        if h.as_byte_array() == expected_hash {
            return PublicKey::from_slice(candidate).ok();
        }
    }
    None
}

/// Return the eligible BIP-352 input public key, or None for ineligible types.
pub fn extract_pubkey_from_input(
    prevout_script: &[u8],
    script_sig: &[u8],
    witness: &[&[u8]],
) -> Option<PublicKey> {
    if is_p2wpkh(prevout_script) {
        if witness.len() == 2 && witness[1].len() == 33 {
            return PublicKey::from_slice(witness[1]).ok();
        }
    } else if is_p2tr(prevout_script) {
        if is_p2tr_key_path(witness) {
            let x_only_bytes = &prevout_script[2..34];
            let mut full_key = [0u8; 33];
            full_key[0] = 0x02;
            full_key[1..].copy_from_slice(x_only_bytes);
            return PublicKey::from_slice(&full_key).ok();
        }
    } else if is_p2pkh(prevout_script) {
        let expected_hash: &[u8; 20] = prevout_script[3..23].try_into().ok()?;
        return extract_pubkey_from_scriptsig(script_sig, expected_hash);
    } else if is_p2sh(prevout_script)
        && !witness.is_empty()
        && witness.len() == 2
        && witness[1].len() == 33
    {
        return PublicKey::from_slice(witness[1]).ok();
    }

    None
}

pub struct InputData<'a> {
    pub prevout_script: &'a [u8],
    pub script_sig: &'a [u8],
    pub witness: Vec<&'a [u8]>,
    pub outpoint: [u8; 36],
}

pub struct FoundOutput {
    pub vout: u32,
    pub x_only_pubkey: XOnlyPublicKey,
    pub k: u32,
}

pub struct OutputData<'a> {
    pub vout: u32,
    pub value: i64,
    pub script_pubkey: &'a [u8],
}

pub struct TransactionData<'a> {
    pub txid: [u8; 32],
    pub inputs: Vec<InputData<'a>>,
    pub outputs: Vec<OutputData<'a>>,
}

pub struct FoundPayment {
    pub txid: [u8; 32],
    pub vout: u32,
    pub x_only_pubkey: XOnlyPublicKey,
    pub k: u32,
    pub amount: i64,
}

pub fn scan_transaction<C: Verification>(
    secp: &Secp256k1<C>,
    scan_key: &ScanKey,
    spend_key: &SpendKey,
    inputs: &[InputData],
    taproot_outputs: &[(u32, XOnlyPublicKey)],
    labeled_spend_keys: &[SpendKey],
) -> Vec<FoundOutput> {
    if inputs.is_empty() || taproot_outputs.is_empty() {
        return vec![];
    }

    let mut pubkeys: Vec<PublicKey> = Vec::new();
    let mut smallest_outpoint: Option<[u8; 36]> = None;

    for input in inputs {
        let witness_refs: Vec<&[u8]> = input.witness.to_vec();
        if let Some(pk) =
            extract_pubkey_from_input(input.prevout_script, input.script_sig, &witness_refs)
        {
            pubkeys.push(pk);
        }

        // Track the lexicographically smallest outpoint among ALL inputs
        match &smallest_outpoint {
            None => smallest_outpoint = Some(input.outpoint),
            Some(current) => {
                if input.outpoint[..] < current[..] {
                    smallest_outpoint = Some(input.outpoint);
                }
            }
        }
    }

    if pubkeys.is_empty() {
        return vec![];
    }

    let smallest_outpoint = match smallest_outpoint {
        Some(op) => op,
        None => return vec![],
    };

    let a_sum = match pubkeys.len() {
        1 => pubkeys[0],
        _ => {
            let refs: Vec<&PublicKey> = pubkeys.iter().collect();
            match PublicKey::combine_keys(&refs) {
                Ok(combined) => combined,
                Err(_) => return vec![],
            }
        }
    };

    let input_hash = compute_input_hash(smallest_outpoint, a_sum);
    let shared_secret = match compute_shared_secret(secp, *scan_key, input_hash, a_sum) {
        Ok(ss) => ss,
        Err(_) => return vec![],
    };

    // All spend keys share the same shared secret and k counter — the sender
    // increments k across every recipient in the same scan-key group.
    let all_spend_keys: Vec<&SpendKey> = std::iter::once(spend_key)
        .chain(labeled_spend_keys.iter())
        .collect();

    let mut found: Vec<FoundOutput> = Vec::new();
    let mut k: u32 = 0;

    loop {
        let mut matched = false;
        'outer: for sk in &all_spend_keys {
            let expected_key = match derive_output_pubkey(secp, shared_secret, **sk, k) {
                Ok(key) => key,
                Err(_) => continue,
            };
            for &(vout, ref output_key) in taproot_outputs {
                if *output_key == expected_key {
                    found.push(FoundOutput {
                        vout,
                        x_only_pubkey: expected_key,
                        k,
                    });
                    matched = true;
                    break 'outer;
                }
            }
        }

        if matched {
            k += 1;
        } else {
            break;
        }
    }

    found
}

pub fn scan_block<C: Verification>(
    secp: &Secp256k1<C>,
    scan_key: &ScanKey,
    spend_key: &SpendKey,
    transactions: &[TransactionData],
) -> Vec<FoundPayment> {
    let mut payments = Vec::new();

    for tx in transactions {
        let taproot_outputs: Vec<(u32, XOnlyPublicKey)> = tx
            .outputs
            .iter()
            .filter(|o| is_p2tr(o.script_pubkey))
            .filter_map(|o| {
                XOnlyPublicKey::from_slice(&o.script_pubkey[2..34])
                    .ok()
                    .map(|key| (o.vout, key))
            })
            .collect();

        if taproot_outputs.is_empty() {
            continue;
        }

        let found = scan_transaction(secp, scan_key, spend_key, &tx.inputs, &taproot_outputs, &[]);

        for f in found {
            let amount = tx
                .outputs
                .iter()
                .find(|o| o.vout == f.vout)
                .map(|o| o.value)
                .unwrap_or(0);

            payments.push(FoundPayment {
                txid: tx.txid,
                vout: f.vout,
                x_only_pubkey: f.x_only_pubkey,
                k: f.k,
                amount,
            });
        }
    }

    payments
}
