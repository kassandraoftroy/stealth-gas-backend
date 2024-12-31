mod collectors;
mod rsasigner;
mod keyencoder;

use blind_rsa_signatures::{KeyPair, SecretKey};
use collectors::{BuyGasTicketsParser, Collector, NativeTransfersParser, SendGasTicketsParser};
use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::contract::{ContractInstance, Interface};
use alloy::json_abi::JsonAbi;
use sqlx::PgPool;
use std::env;
use tokio;
use futures;
use crate::rsasigner::BlindSigner;
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use crate::keyencoder::{encode_public_key_to_hex, decode_hex_to_public_key};
use hex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    // Load environment variables
    let rpc_url = env::var("RPC_URL").expect("RPC_URL not set");
    let contract_address: Address = env::var("CONTRACT_ADDRESS")
        .expect("CONTRACT_ADDRESS not set")
        .parse()
        .expect("Invalid CONTRACT_ADDRESS");
    let start_block: u64 = env::var("START_BLOCK")
        .expect("START_BLOCK not set")
        .parse()
        .expect("START_BLOCK must be an integer");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let b64 = std::env::var("RSA_PRIVATE_KEY_B64").expect("RSA_PRIVATE_KEY_B64 not set");

    // Decode base64 into raw bytes
    let pem_bytes = BASE64_STANDARD
        .decode(&b64)
        .expect("Invalid Base64 in RSA_PRIVATE_KEY_BASE64");

    // Convert raw bytes to UTF-8 PEM string
    let pem = String::from_utf8(pem_bytes).expect("Decoded key is not valid UTF-8");

    // Load RSA key pair
    let sk = SecretKey::from_pem(&pem).expect("Invalid RSA private key");
    let pk = sk.public_key().expect("Failed to get public key");
    
    let hex1 = encode_public_key_to_hex(&pk);

    // Connect to the PostgreSQL database
    let db_pool = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db_pool).await?;

    let ws = WsConnect::new(rpc_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;

    let abi = JsonAbi::parse(   
        ["function coordinatorPubKey() external view returns (bytes memory)"]
    ).expect("Failed to parse ABI");

    // Create a contract instance to call coordinatorPubKey()
    let contract = ContractInstance::new(
        contract_address,
        provider.clone(),
        Interface::new(abi)
    );

    // Make the static call to get the coordinator's public key
    let contract_pubkey_val = contract
        .function("coordinatorPubKey", &[])
        .expect("Failed to create method call")
        .call()
        .await
        .expect("Failed to call coordinatorPubKey");
    let contract_pubkey = contract_pubkey_val[0]
        .as_bytes()
        .expect("Expected bytes output");
    let contract_pubkey_hex = "0x".to_string() + &hex::encode(contract_pubkey);
    
    // Decode the contract's public key and compare
    let contract_pk = decode_hex_to_public_key(&contract_pubkey_hex);
    if contract_pk != pk || contract_pubkey_hex != hex1 {
        panic!("env rsa key does not match onchain rsa pubkey");
    }

    let key_pair = KeyPair { pk, sk };
    let signer = Arc::new(BlindSigner::new(key_pair));
    
    // Create collectors for each event type
    let buy_gas_tickets_collector = Collector::new(
        provider.clone(),
        BuyGasTicketsParser::new(signer.clone()),
        vec![contract_address],
        start_block,
        db_pool.clone(),
    );

    let send_gas_tickets_collector = Collector::new(
        provider.clone(),
        SendGasTicketsParser,
        vec![contract_address],
        start_block,
        db_pool.clone(),
    );

    let native_transfers_collector = Collector::new(
        provider.clone(),
        NativeTransfersParser,
        vec![contract_address],
        start_block,
        db_pool.clone(),
    );

    // Spawn tasks for each collector
    tokio::spawn(buy_gas_tickets_collector.run());
    tokio::spawn(send_gas_tickets_collector.run());
    tokio::spawn(native_transfers_collector.run());

    // Keep the program alive
    futures::future::pending::<()>().await;

    Ok(())
}

