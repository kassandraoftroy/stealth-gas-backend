mod collectors;
mod rsasigner;
mod keyencoder;
mod fulfiller;
mod gas_station_helper;
mod types;

use fulfiller::Fulfiller;
use blind_rsa_signatures::{KeyPair, SecretKey};
use collectors::{BuyGasTicketsParser, Collector, NativeTransfersParser, SendGasTicketsParser};
use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::contract::{ContractInstance, Interface};
use alloy::json_abi::JsonAbi;
use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
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
    let rpc_url_clone = rpc_url.clone();
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
    let eth_priv = env::var("ETH_PRIVATE_KEY").expect("ETH_PRIVATE_KEY must be set");
    let chain_id_str = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
    let chain_id = chain_id_str.parse::<u64>().expect("CHAIN_ID must be an integer");

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
        [
            "function coordinatorPubKey() external view returns (bytes memory)",
            "function ticketCost() external view returns (uint256)",
            "function shippingCost() external view returns (uint256)",
        ]
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
    
    // let ticket_cost_val = contract
    //     .function("ticketCost", &[])
    //     .expect("Failed to create method call")
    //     .call()
    //     .await
    //     .expect("Failed to call ticketCost");
    
    // let shipping_cost_val = contract
    //     .function("shippingCost", &[])
    //     .expect("Failed to create method call")
    //     .call()
    //     .await
    //     .expect("Failed to call shippingCost");

    // let (ticket_cost, _) = ticket_cost_val[0].as_uint().expect("Failed to get uint");
    // let (shipping_cost, _) = shipping_cost_val[0].as_uint().expect("Failed to get uint");
    
    // Decode the contract's public key and compare
    let contract_pk = decode_hex_to_public_key(&contract_pubkey_hex);
    if contract_pk != pk || contract_pubkey_hex != hex1 {
        panic!("env rsa key does not match onchain rsa pubkey");
    }

    let rsa_key_pair = KeyPair { pk, sk };
    let rsa_signer = Arc::new(BlindSigner::new(rsa_key_pair));

    let eth_signer: PrivateKeySigner = eth_priv.parse().expect("Failed to parse private key");
    let eth_signer_address = eth_signer.address();
    let eth_wallet = EthereumWallet::from(eth_signer);
    let signer_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(eth_wallet)
        .on_ws(WsConnect::new(rpc_url_clone))
        .await?;

    // Create collectors for each event type
    let buy_gas_tickets_collector = Collector::new(
        provider.clone(),
        BuyGasTicketsParser::new(rsa_signer.clone()),
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

    let fulfiller = Fulfiller::new(
        db_pool.clone(),
        contract_address,
        eth_signer_address,
        Arc::new(signer_provider),
        chain_id,
    );

    println!("starting coordinator with key: {:?}", contract_pubkey_hex);

    let buy_gas_tickets_collector_clone = buy_gas_tickets_collector.clone();
    let send_gas_tickets_collector_clone = send_gas_tickets_collector.clone();

    println!("starting collectors from start block: {}...", start_block);

    tokio::spawn(buy_gas_tickets_collector.run());
    tokio::spawn(send_gas_tickets_collector.run());
    tokio::spawn(native_transfers_collector.run());

    println!("waiting for collectors to be live...");
    while !buy_gas_tickets_collector_clone.is_live() || !send_gas_tickets_collector_clone.is_live() {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    println!("starting fulfiller (sync event states first)...");
    tokio::spawn(async move {
        fulfiller.run().await.unwrap();
    });

    // Keep the program alive
    futures::future::pending::<()>().await;

    Ok(())
}

