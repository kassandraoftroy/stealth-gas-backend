mod collectors;
mod rsasigner;
mod keyencoder;

use blind_rsa_signatures::{KeyPair, SecretKey};
use collectors::{BuyGasTicketsParser, Collector, NativeTransfersParser, SendGasTicketsParser};
use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use sqlx::PgPool;
use std::env;
use tokio;
use futures;
use crate::rsasigner::BlindSigner;
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use crate::keyencoder::{encode_public_key_to_hex, decode_hex_to_public_key};

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
    println!("hex: {}", hex1);

    let pk_check = decode_hex_to_public_key(&hex1);
    println!("pk1: {}", pk_check.to_pem()?);
    println!("pk2: {}", pk.to_pem()?);
    println!("check: {}", pk_check==pk);
    
    let key_pair = KeyPair { pk, sk };
    let signer = Arc::new(BlindSigner::new(key_pair));

    // Connect to the PostgreSQL database
    let db_pool = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db_pool).await?;

    let ws = WsConnect::new(rpc_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;
    
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

