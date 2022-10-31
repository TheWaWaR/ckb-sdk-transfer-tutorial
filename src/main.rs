use std::collections::HashMap;
use std::error::Error as StdErr;

use clap::{Parser, Subcommand};
use rand::Rng;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::{CkbRpcClient, IndexerRpcClient},
    traits::{
        CellQueryOptions, DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, MaturityOption, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, AddressPayload, HumanCapacity, NetworkType, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};

/// # Example:
///     cargo run --release -- gen-key
///     cargo run --release -- query --address <address>
///     cargo run --release -- transfer --sender-key <key-hex> --receiver <address> --capacity 61.0
///     cargo run --release -- query-tx-status --tx-hash <hash>
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a random ecdsa key
    GenKey,
    /// Query the balance of an address
    Query {
        /// The address
        #[clap(long, value_name = "ADDRESS")]
        address: Address,

        /// CKB indexer rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
        ckb_indexer_rpc: String,
    },
    /// Query the transaction status
    QueryTxStatus {
        /// The transaction hash
        #[clap(long, value_name = "HASH")]
        tx_hash: H256,

        /// CKB rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
        ckb_rpc: String,
    },
    /// Transfer some CKB from one sighash address to other address
    Transfer {
        /// The sender private key (hex string)
        #[clap(long, value_name = "KEY")]
        sender_key: H256,

        /// The receiver address
        #[clap(long, value_name = "ADDRESS")]
        receiver: Address,

        /// The capacity to transfer (unit: CKB, example: 102.43)
        #[clap(long, value_name = "CKB")]
        capacity: HumanCapacity,

        /// CKB rpc url
        #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
        ckb_rpc: String,
    },
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::GenKey => {
            let mut rng = rand::thread_rng();
            for _ in 0..1024 {
                let privkey_bytes: [u8; 32] = rng.gen();
                if let Ok(secret_key) = secp256k1::SecretKey::from_slice(&privkey_bytes) {
                    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
                    let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
                    let address_payload = AddressPayload::new_full(
                        ScriptHashType::Type,
                        SIGHASH_TYPE_HASH.pack(),
                        Bytes::from(hash160),
                    );
                    let testnet_address = Address::new(NetworkType::Testnet, address_payload, true);
                    println!("testnet address: {}", testnet_address);
                    println!("secret key: {:#x}", H256(privkey_bytes));
                    break;
                }
            }
        }
        Commands::Query {
            address,
            ckb_indexer_rpc,
        } => {
            let mut client = IndexerRpcClient::new(ckb_indexer_rpc.as_str());
            let mut query = CellQueryOptions::new_lock(Script::from(&address));
            query.maturity = MaturityOption::Both;
            query.min_total_capacity = u64::max_value();
            if let Some(cells_capacity) = client.get_cells_capacity(query.into())? {
                println!("tip number: {}", cells_capacity.block_number.value());
                println!("tip hash: {:#x}", cells_capacity.block_hash);
                println!(
                    "capacity: {} CKB",
                    HumanCapacity(cells_capacity.capacity.value())
                );
            } else {
                println!("address capacity not found");
            }
        }
        Commands::QueryTxStatus { tx_hash, ckb_rpc } => {
            let mut ckb_client = CkbRpcClient::new(ckb_rpc.as_str());
            if let Some(tx_with_status) = ckb_client.get_transaction(tx_hash)? {
                let status = tx_with_status.tx_status;
                println!("status: {:?}", status.status);
                if let Some(hash) = status.block_hash {
                    println!("block hash: {:#x}", hash);
                }
                if let Some(reason) = status.reason {
                    println!("reason: {}", reason);
                }
            } else {
                println!("transaction not found");
            }
        }
        Commands::Transfer {
            sender_key,
            receiver,
            capacity,
            ckb_rpc,
        } => {
            let sender_key = secp256k1::SecretKey::from_slice(sender_key.as_bytes())
                .map_err(|err| format!("invalid sender secret key: {}", err))?;
            let sender = {
                let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
                let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
                Script::new_builder()
                    .code_hash(SIGHASH_TYPE_HASH.pack())
                    .hash_type(ScriptHashType::Type.into())
                    .args(Bytes::from(hash160).pack())
                    .build()
            };

            let tx =
                build_transfer_tx(&receiver, capacity.0, ckb_rpc.as_str(), sender, sender_key)?;

            // Send transaction
            let json_tx = json_types::TransactionView::from(tx);
            let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
            let tx_hash = CkbRpcClient::new(ckb_rpc.as_str())
                .send_transaction(json_tx.inner, outputs_validator)
                .expect("send transaction");
            println!(">>> tx sent! {:#x} <<<", tx_hash);
        }
    }

    Ok(())
}

fn build_transfer_tx(
    receiver: &Address,
    capacity: u64,
    ckb_rpc: &str,
    sender: Script,
    sender_key: secp256k1::SecretKey,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(ckb_rpc);
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(Script::from(receiver))
        .capacity(capacity.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, still_locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}
