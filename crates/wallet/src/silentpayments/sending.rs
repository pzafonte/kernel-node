use std::collections::HashMap;
use std::fmt;

use bdk_tx::{
    selection_algorithm_lowest_fee_bnb, ChangeScript, Input, InputCandidates, Output, PsbtParams,
    SelectorParams,
};
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::{predict_weight, InputWeightPrediction};
use bitcoin::{
    taproot, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Weight, Witness,
};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::sending::calculate_partial_secret;
use silentpayments::SilentPaymentAddress;

use crate::silentpayments::wallet::{Coin, Wallet};

const TR_KEYSPEND_SATISFACTION_WU: usize = 66;
const P2TR_SPK_LEN: usize = 34;

#[derive(Debug)]
pub enum SendError {
    WatchOnly,
    NoSpendableCoins,
    DustAmount { amount: Amount, dust: Amount },
    InsufficientFunds { needed: Amount, available: Amount },
    NetworkMismatch,
    OutputDerivation,
    TxBuild(String),
    SilentPayments(::silentpayments::Error),
    Secp(secp256k1::Error),
    Sighash(bitcoin::sighash::TaprootError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::WatchOnly => {
                write!(f, "wallet is watch-only: no spend secret to sign with")
            }
            SendError::NoSpendableCoins => write!(f, "no spendable coins"),
            SendError::DustAmount { amount, dust } => write!(
                f,
                "amount {} sats is below the dust limit of {} sats",
                amount.to_sat(),
                dust.to_sat()
            ),
            SendError::InsufficientFunds { needed, available } => write!(
                f,
                "insufficient funds: need {} sats, have {} sats",
                needed.to_sat(),
                available.to_sat()
            ),
            SendError::NetworkMismatch => {
                write!(f, "recipient address is for a different network")
            }
            SendError::OutputDerivation => write!(f, "recipient output key was not derived"),
            SendError::TxBuild(e) => write!(f, "transaction build error: {e}"),
            SendError::SilentPayments(e) => write!(f, "silent payments error: {e}"),
            SendError::Secp(e) => write!(f, "secp256k1 error: {e}"),
            SendError::Sighash(e) => write!(f, "sighash error: {e}"),
        }
    }
}

impl std::error::Error for SendError {}

impl From<::silentpayments::Error> for SendError {
    fn from(e: ::silentpayments::Error) -> Self {
        SendError::SilentPayments(e)
    }
}

impl From<secp256k1::Error> for SendError {
    fn from(e: secp256k1::Error) -> Self {
        SendError::Secp(e)
    }
}

impl From<bitcoin::sighash::TaprootError> for SendError {
    fn from(e: bitcoin::sighash::TaprootError) -> Self {
        SendError::Sighash(e)
    }
}

struct SpendableCoin<'a> {
    outpoint: OutPoint,
    coin: &'a Coin,
}

impl Wallet {
    pub fn build_transaction(
        &self,
        recipient: SilentPaymentAddress,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Transaction, SendError> {
        if recipient.get_network() != self.network {
            return Err(SendError::NetworkMismatch);
        }
        let spend_secret = self.spend_secret.ok_or(SendError::WatchOnly)?;
        let keys = self.keys.as_ref().ok_or(SendError::WatchOnly)?;
        let change_address = keys.receiver.get_change_address();

        let coins: Vec<SpendableCoin> = self
            .utxos
            .iter()
            .filter(|(outpoint, coin)| coin.spent_by.is_none() && !self.reserved.contains(outpoint))
            .map(|(outpoint, coin)| SpendableCoin {
                outpoint: *outpoint,
                coin,
            })
            .collect();

        build_transaction(
            &spend_secret,
            recipient,
            amount,
            fee_rate,
            change_address,
            &coins,
        )
    }
}

fn build_transaction(
    spend_secret: &SecretKey,
    recipient: SilentPaymentAddress,
    amount: Amount,
    fee_rate: FeeRate,
    change_address: SilentPaymentAddress,
    coins: &[SpendableCoin],
) -> Result<Transaction, SendError> {
    if coins.is_empty() {
        return Err(SendError::NoSpendableCoins);
    }
    let secp = Secp256k1::new();

    let dust = p2tr_dust(spend_secret, &secp);
    if amount < dust {
        return Err(SendError::DustAmount { amount, dust });
    }

    let placeholder_recipient = p2tr_script(probe_key(&secp, 1));
    let placeholder_change = p2tr_script(probe_key(&secp, 2));

    let by_outpoint: HashMap<OutPoint, &Coin> =
        coins.iter().map(|c| (c.outpoint, c.coin)).collect();

    let inputs = coins
        .iter()
        .map(|c| {
            let psbt_input = bitcoin::psbt::Input {
                witness_utxo: Some(TxOut {
                    value: c.coin.value,
                    script_pubkey: c.coin.script_pubkey.clone(),
                }),
                ..Default::default()
            };
            Input::from_psbt_input(
                c.outpoint,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                psbt_input,
                TR_KEYSPEND_SATISFACTION_WU,
                None,
                false,
                None,
            )
            .map_err(|e| SendError::TxBuild(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let selection = InputCandidates::new([], inputs)
        .into_selection(
            selection_algorithm_lowest_fee_bnb(FeeRate::from_sat_per_vb(1).unwrap(), 100_000),
            SelectorParams::new(
                fee_rate,
                vec![Output::with_script(placeholder_recipient.clone(), amount)],
                ChangeScript::from_script(
                    placeholder_change.clone(),
                    Weight::from_wu(TR_KEYSPEND_SATISFACTION_WU as u64),
                ),
            ),
        )
        .map_err(|_| {
            let available: Amount = coins.iter().map(|c| c.coin.value).sum();
            let weight = predict_weight(
                std::iter::repeat_n(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, coins.len()),
                [P2TR_SPK_LEN, P2TR_SPK_LEN],
            );
            let fee = fee_rate.fee_wu(weight).unwrap_or(Amount::ZERO);
            SendError::InsufficientFunds {
                needed: amount + fee,
                available,
            }
        })?;

    let mut psbt = selection
        .create_psbt(PsbtParams::default())
        .map_err(|e| SendError::TxBuild(e.to_string()))?;

    let selected: Vec<&Coin> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| {
            by_outpoint
                .get(&txin.previous_output)
                .copied()
                .ok_or(SendError::OutputDerivation)
        })
        .collect::<Result<_, _>>()?;

    let signing_keys: Vec<SecretKey> = selected
        .iter()
        .map(|c| spend_secret.add_tweak(&c.tweak))
        .collect::<Result<_, secp256k1::Error>>()?;
    let input_keys: Vec<(SecretKey, bool)> = signing_keys.iter().map(|k| (*k, true)).collect();
    let outpoints: Vec<(String, u32)> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| {
            (
                txin.previous_output.txid.to_string(),
                txin.previous_output.vout,
            )
        })
        .collect();
    let partial_secret = calculate_partial_secret(&input_keys, &outpoints)?;

    let has_change = psbt
        .unsigned_tx
        .output
        .iter()
        .any(|o| o.script_pubkey == placeholder_change);
    let mut recipients = vec![recipient];
    if has_change {
        recipients.push(change_address);
    }
    let recipient_pubkeys = generate_recipient_pubkeys(recipients, partial_secret)?;
    let real_recipient = sp_output_script(&recipient_pubkeys, recipient)?;
    let real_change = if has_change {
        Some(sp_output_script(&recipient_pubkeys, change_address)?)
    } else {
        None
    };

    for out in psbt.unsigned_tx.output.iter_mut() {
        if out.script_pubkey == placeholder_recipient {
            out.script_pubkey = real_recipient.clone();
        } else if out.script_pubkey == placeholder_change {
            out.script_pubkey = real_change.clone().expect("change script derived");
        }
    }

    let prevouts: Vec<TxOut> = selected
        .iter()
        .map(|c| TxOut {
            value: c.value,
            script_pubkey: c.script_pubkey.clone(),
        })
        .collect();
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    for (i, signing_key) in signing_keys.iter().enumerate() {
        let sighash = cache.taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )?;
        let keypair = Keypair::from_secret_key(&secp, signing_key);
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        let sig = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };
        psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[sig.serialize()]));
    }

    psbt.extract_tx().map_err(|e| SendError::TxBuild(e.to_string()))
}

fn probe_key(secp: &Secp256k1<secp256k1::All>, byte: u8) -> XOnlyPublicKey {
    SecretKey::from_slice(&[byte; 32])
        .unwrap()
        .x_only_public_key(secp)
        .0
}

fn sp_output_script(
    pubkeys: &HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>>,
    address: SilentPaymentAddress,
) -> Result<ScriptBuf, SendError> {
    let xonly = pubkeys
        .get(&address)
        .and_then(|keys| keys.first())
        .ok_or(SendError::OutputDerivation)?;
    Ok(p2tr_script(*xonly))
}

fn p2tr_script(output_key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key))
}

fn p2tr_dust(spend_secret: &SecretKey, secp: &Secp256k1<secp256k1::All>) -> Amount {
    let probe = spend_secret.x_only_public_key(secp).0;
    p2tr_script(probe).minimal_non_dust()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Parity, Scalar};
    use bitcoin::Txid;
    use silentpayments::Network;

    use crate::silentpayments::build_receiver;

    fn even_secret(bytes: [u8; 32]) -> SecretKey {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&bytes).unwrap();
        match key.x_only_public_key(&secp).1 {
            Parity::Odd => key.negate(),
            Parity::Even => key,
        }
    }

    fn address(scan: SecretKey, spend: SecretKey) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        let spend_pub = spend.public_key(&secp);
        build_receiver(&scan, spend_pub, Network::Regtest)
            .unwrap()
            .get_receiving_address()
    }

    fn owned_coin(spend_secret: &SecretKey, tweak: Scalar, value: Amount) -> Coin {
        let secp = Secp256k1::new();
        let output_key = spend_secret.add_tweak(&tweak).unwrap().x_only_public_key(&secp).0;
        Coin {
            value,
            script_pubkey: p2tr_script(output_key),
            tweak,
            label: None,
            block_height: 1,
            spent_by: None,
        }
    }

    #[test]
    fn signs_a_spendable_taproot_input() {
        let secp = Secp256k1::new();
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let change_address = build_receiver(
            &scan_secret,
            spend_secret.public_key(&secp),
            Network::Regtest,
        )
        .unwrap()
        .get_change_address();

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let coins = [SpendableCoin {
            outpoint,
            coin: &coin,
        }];

        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);
        let tx = build_transaction(
            &spend_secret,
            recipient,
            amount,
            fee_rate,
            change_address,
            &coins,
        )
        .unwrap();

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, amount);

        let fee = coin.value - tx.output.iter().map(|o| o.value).sum::<Amount>();
        assert!(fee > Amount::ZERO);

        let prevouts = [TxOut {
            value: coin.value,
            script_pubkey: coin.script_pubkey.clone(),
        }];
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let witness = &tx.input[0].witness;
        let sig = secp256k1::schnorr::Signature::from_slice(&witness[0][..64]).unwrap();
        let output_key = spend_secret.add_tweak(&tweak).unwrap().x_only_public_key(&secp).0;
        secp.verify_schnorr(&sig, &message, &output_key)
            .expect("signature must verify against the output key");
    }

    #[test]
    fn rejects_amount_over_balance() {
        let spend_secret = even_secret([0x02; 32]);
        let change_address = address(even_secret([0x01; 32]), spend_secret);
        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(10_000));
        let coins = [SpendableCoin {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 0,
            },
            coin: &coin,
        }];

        let err = build_transaction(
            &spend_secret,
            recipient,
            Amount::from_sat(20_000),
            FeeRate::from_sat_per_vb(2).unwrap(),
            change_address,
            &coins,
        )
        .unwrap_err();
        assert!(matches!(err, SendError::InsufficientFunds { .. }));
    }

    #[test]
    fn reserved_coins_are_not_reselected() {
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let mut wallet = Wallet::new(Network::Regtest);
        wallet.import_signing_keys(scan_secret, spend_secret).unwrap();

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        wallet.utxos.insert(outpoint, coin);

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);

        let tx = wallet
            .build_transaction(recipient, amount, fee_rate)
            .unwrap();
        wallet.reserve_coins(tx.input.iter().map(|i| i.previous_output));

        let err = wallet
            .build_transaction(recipient, amount, fee_rate)
            .unwrap_err();
        assert!(matches!(err, SendError::NoSpendableCoins));
    }

    #[test]
    fn released_coins_are_selectable_again() {
        let scan_secret = even_secret([0x01; 32]);
        let spend_secret = even_secret([0x02; 32]);
        let mut wallet = Wallet::new(Network::Regtest);
        wallet.import_signing_keys(scan_secret, spend_secret).unwrap();

        let tweak = Scalar::from_be_bytes([0x05; 32]).unwrap();
        let coin = owned_coin(&spend_secret, tweak, Amount::from_sat(100_000));
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        wallet.utxos.insert(outpoint, coin);

        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let amount = Amount::from_sat(50_000);

        let tx = wallet.build_transaction(recipient, amount, fee_rate).unwrap();
        let outpoints: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();

        wallet.reserve_coins(outpoints.iter().copied());
        assert!(matches!(
            wallet.build_transaction(recipient, amount, fee_rate),
            Err(SendError::NoSpendableCoins)
        ));

        wallet.release_coins(outpoints);
        assert!(wallet.build_transaction(recipient, amount, fee_rate).is_ok());
    }

    #[test]
    fn rejects_empty_wallet() {
        let spend_secret = even_secret([0x02; 32]);
        let change_address = address(even_secret([0x01; 32]), spend_secret);
        let recipient = address(even_secret([0x03; 32]), even_secret([0x04; 32]));
        let err = build_transaction(
            &spend_secret,
            recipient,
            Amount::from_sat(1_000),
            FeeRate::from_sat_per_vb(2).unwrap(),
            change_address,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SendError::NoSpendableCoins));
    }
}
