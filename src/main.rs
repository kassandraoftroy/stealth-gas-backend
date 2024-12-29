mod collectors;

use collectors::{BuyGasTicketsParser, Collector, NativeTransfersParser, SendGasTicketsParser};
use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use sqlx::PgPool;
use std::env;
use tokio;
use futures;

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

    // Connect to the PostgreSQL database
    let db_pool = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db_pool).await?;

    let ws = WsConnect::new(rpc_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;
    // Create collectors for each event type
    let buy_gas_tickets_collector = Collector::new(
        provider.clone(),
        BuyGasTicketsParser,
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

