use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, U256},
    providers::{Provider, RootProvider},
    pubsub::PubSubFrontend,
    rpc::types::{Filter, Log},
    sol,
    sol_types::SolEvent,
    rpc::types::BlockNumberOrTag::Finalized,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use crate::rsasigner::BlindSigner;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Collector<T: EventParser> {
    provider: Arc<RootProvider<PubSubFrontend>>,
    parser: T,
    filter: Filter,
    db_pool: PgPool,
}

sol! {
    #[sol(rpc)]
    interface IStealthGasStation {
        event BuyGasTickets(bytes[] blinded);
        event SendGasTickets(bytes32[] ids, bytes[] signed);
        event NativeTransfers(uint256[] amounts, address[] targets, bytes d);
    }
}

pub trait EventParser {
    fn event_topic(&self) -> B256;
    fn event_kind(&self) -> String;
    fn parse_event(&self, log: Log) -> serde_json::Value;
}

impl<T: EventParser> Collector<T> {
    pub fn new(
        provider: RootProvider<PubSubFrontend>,
        parser: T,
        targets: Vec<Address>,
        start_block: u64,
        db_pool: PgPool,
    ) -> Self {
        let filter = Filter::new()
            .address(targets)
            .from_block(start_block);
        
        Self {
            provider: Arc::new(provider),
            parser,
            filter,
            db_pool,
        }
    }

    // pub fn filter(&self) -> &Filter {
    //     &self.filter
    // }
    // pub fn provider(&self) -> &Arc<RootProvider<PubSubFrontend>> {
    //     &self.provider
    // }
    
    pub fn event_topic(&self) -> B256 {
        self.parser.event_topic()
    }
    pub fn event_kind(&self) -> String {
        self.parser.event_kind()
    }

    pub async fn run(self) {
        // Step 1: Process historical logs
        if let Err(err) = self.process_past_logs().await {
            eprintln!("Error processing past logs: {}", err);
        }

        // Step 2: Transition to live log subscription
        if let Err(err) = self.process_live_logs().await {
            eprintln!("Error processing live logs: {}", err);
        }
    }

    async fn process_past_logs(&self) -> anyhow::Result<()> {
        // Fetch current block number
        let finalized_block = self.provider.get_block_by_number(Finalized, false).await?;
        let finalized_block_number = finalized_block.unwrap().header.number.unwrap();
        
        // Adjust filter to fetch logs up to the latest block
        let filter = self.filter.clone().to_block(finalized_block_number);

        // Fetch logs
        let logs = self.provider.get_logs(&filter).await?;
        for log in logs {
            let event_data = self.parser.parse_event(log.clone());
            if !event_data.is_null() {
                self.store_event(log, event_data).await;
            }
        }
        Ok(())
    }

    async fn process_live_logs(self) -> anyhow::Result<()> {
        let mut last_finalized_block = self.provider
            .get_block_by_number(Finalized, false)
            .await?
            .unwrap()
            .header
            .number
            .unwrap();

        loop {
            // Fetch the most recent finalized block
            let finalized_block = self.provider
                .get_block_by_number(Finalized, false)
                .await?
                .unwrap()
                .header
                .number
                .unwrap();

            if finalized_block > last_finalized_block {
                // Fetch logs for new blocks
                let filter = self.filter.clone()
                    .from_block(last_finalized_block - 64)
                    .to_block(finalized_block); // Up to the most recent finalized block

                let logs = self.provider.get_logs(&filter).await?;
                for log in logs {
                    let event_data = self.parser.parse_event(log.clone());

                    if !event_data.is_null() {
                        self.store_event(log, event_data).await;
                    }
                }

                // Update the last finalized block
                last_finalized_block = finalized_block;

                // Sleep for 2 minutes before polling again
                tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
            }
        }
    }

    async fn store_event(&self, log: Log, event_data: serde_json::Value) {
        let query = "INSERT INTO events (removed, event_topic, event_kind, event_state, block_number, block_timestamp, transaction_hash, transaction_index, log_index, event_data) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT (transaction_hash, log_index)
                     DO UPDATE SET
                     removed = EXCLUDED.removed,
                     block_number = EXCLUDED.block_number,
                     block_timestamp = EXCLUDED.block_timestamp,
                     transaction_index = EXCLUDED.transaction_index;";
        if let Err(err) = sqlx::query(query)
            .bind(log.removed)
            .bind(self.event_topic().to_string())
            .bind(self.event_kind())
            .bind("INDEXED".to_owned())
            .bind(log.block_number.unwrap_or_default() as i64)
            .bind(log.block_timestamp.unwrap_or_default() as i64)
            .bind(log.transaction_hash.unwrap_or_default().to_string())
            .bind(log.transaction_index.unwrap_or_default() as i32)
            .bind(log.log_index.unwrap_or_default() as i32)
            .bind(event_data)
            .execute(&self.db_pool)
            .await
        {
            eprintln!("Failed to insert event into database: {}", err);
        }
    }
}

// Define Parsers for the events
#[derive(Serialize, Deserialize)]
struct BuyGasTicketsEvent {
    blinded: Vec<Bytes>,
    signed: Vec<Bytes>,
    ids: Vec<Bytes>,
}
pub struct BuyGasTicketsParser {
    signer: Arc<BlindSigner>,
}

impl BuyGasTicketsParser {
    pub fn new(signer: Arc<BlindSigner>) -> Self {
        Self { signer }
    }
}

impl EventParser for BuyGasTicketsParser {
    fn event_topic(&self) -> B256 {
        IStealthGasStation::BuyGasTickets::SIGNATURE_HASH
    }

    fn event_kind(&self) -> String {
        "BuyGasTickets".to_owned()
    }

    fn parse_event(&self, log: Log) -> serde_json::Value {
        match log.log_decode::<IStealthGasStation::BuyGasTickets>() {
            Ok(decoded_log) => {
                // Blind message signing
                let blinded_messages = decoded_log.inner.blinded.clone();
                let signed_blind_msgs = match self.signer.sign_blinded_messages(blinded_messages.clone()) {
                    Ok(msgs) => msgs,
                    Err(e) => {
                        eprintln!("Failed to sign blinded messages: {}", e);
                        return serde_json::Value::Null;
                    }
                };
                let message_ids = blinded_messages
                    .iter()
                    .map(|msg| Bytes::from(Sha256::digest(msg).to_vec()))
                    .collect::<Vec<_>>();

                // Populate event data
                let event = BuyGasTicketsEvent {
                    blinded: blinded_messages,
                    signed: signed_blind_msgs,
                    ids: message_ids,
                };

                serde_json::to_value(event).unwrap_or(serde_json::Value::Null)
            }
            Err(e) => {
                eprintln!("Failed to decode BuyGasTickets event: {}", e);
                serde_json::Value::Null
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SendGasTicketsEvent {
    ids: Vec<FixedBytes<32>>,
    signed: Vec<Bytes>,
}
pub struct SendGasTicketsParser;

impl EventParser for SendGasTicketsParser {
    fn event_topic(&self) -> B256 {
        IStealthGasStation::SendGasTickets::SIGNATURE_HASH
    }

    fn event_kind(&self) -> String {
        "SendGasTickets".to_owned()
    }

    fn parse_event(&self, log: Log) -> serde_json::Value {
        match log.log_decode::<IStealthGasStation::SendGasTickets>() {
            Ok(decoded_log) => {
                let event = SendGasTicketsEvent {
                    ids: decoded_log.inner.ids.clone(),
                    signed: decoded_log.inner.signed.clone(),
                };
                serde_json::to_value(event).unwrap_or(serde_json::Value::Null)
            }
            Err(e) => {
                eprintln!("Failed to decode SendGasTickets event: {}", e);
                serde_json::Value::Null
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct NativeTransfersEvent {
    amounts: Vec<U256>,
    targets: Vec<Address>,
    data: Bytes,
}
pub struct NativeTransfersParser;

impl EventParser for NativeTransfersParser {
    fn event_topic(&self) -> B256 {
        IStealthGasStation::NativeTransfers::SIGNATURE_HASH
    }

    fn event_kind(&self) -> String {
        "NativeTransfers".to_owned()
    }

    fn parse_event(&self, log: Log) -> serde_json::Value {
        match log.log_decode::<IStealthGasStation::NativeTransfers>() {
            Ok(decoded_log) => {
                let event = NativeTransfersEvent {
                    amounts: decoded_log.inner.amounts.clone(),
                    targets: decoded_log.inner.targets.clone(),
                    data: decoded_log.inner.d.clone(),
                };
                serde_json::to_value(event).unwrap_or(serde_json::Value::Null)
            }
            Err(e) => {
                eprintln!("Failed to decode NativeTransfers event: {}", e);
                serde_json::Value::Null
            }
        }
    }
}