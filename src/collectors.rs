use crate::rsasigner::BlindSigner;
use crate::sql::DbClient;
use alloy::{
    primitives::{Address, Bytes, FixedBytes, B256, U256},
    providers::{Provider, RootProvider},
    pubsub::PubSubFrontend,
    rpc::types::{BlockNumberOrTag::Finalized, BlockTransactionsKind::Full},
    rpc::types::{Filter, Log},
    sol,
    sol_types::SolEvent,
};
use eth_stealth_gas_tickets::BlindedSignature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct Collector<T: EventParser> {
    provider: Arc<RootProvider<PubSubFrontend>>,
    parser: T,
    filter: Filter,
    db_client: DbClient,
    live: Arc<AtomicBool>,
}

sol! {
    #[sol(rpc)]
    interface IStealthGasStation {
        event BuyGasTickets(bytes[] blinded);
        event SendGasTickets(bytes32[] ids, bytes[] signed);
        event NativeTransfers(uint256[] amounts, address[] targets, bytes d);
    }
}

/// Computes a canonical hash for a list of IDs (FixedBytes<32>)
pub fn compute_ids_hash(ids: &[FixedBytes<32>]) -> String {
    let mut hasher = Sha256::new();
    for id in ids {
        hasher.update(id.as_slice());
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

pub trait EventParser: Clone {
    fn event_topic(&self) -> B256;
    fn event_kind(&self) -> String;
    fn parse_event(&self, log: Log) -> (serde_json::Value, String);
}

impl<T: EventParser> Collector<T> {
    pub fn new(
        provider: RootProvider<PubSubFrontend>,
        parser: T,
        targets: Vec<Address>,
        start_block: u64,
        db_client: DbClient,
    ) -> Self {
        let filter = Filter::new().address(targets).from_block(start_block);

        Self {
            provider: Arc::new(provider),
            parser,
            filter,
            db_client,
            live: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn event_topic(&self) -> B256 {
        self.parser.event_topic()
    }
    pub fn event_kind(&self) -> String {
        self.parser.event_kind()
    }
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    pub async fn run(self) {
        // Step 1: Process historical logs
        if let Err(err) = self.process_past_logs().await {
            eprintln!("Error processing past logs: {}", err);
        }

        // Mark the collector as live after finishing past logs
        self.live.store(true, Ordering::Relaxed);

        // Step 2: Transition to live log subscription
        if let Err(err) = self.process_live_logs().await {
            eprintln!("Error processing live logs: {}", err);
        }
    }

    async fn process_past_logs(&self) -> anyhow::Result<()> {
        // Fetch current block number
        let finalized_block = self.provider.get_block_by_number(Finalized, Full).await?;
        let finalized_block_number = finalized_block.unwrap().header.number;

        // Adjust filter to fetch logs up to the latest block
        let filter = self.filter.clone().to_block(finalized_block_number);

        // Fetch logs
        let logs = self.provider.get_logs(&filter).await?;
        for log in logs {
            let (event_data, match_id) = self.parser.parse_event(log.clone());
            if !event_data.is_null() {
                self.store_event(log, event_data, match_id).await;
            }
        }
        Ok(())
    }

    async fn process_live_logs(self) -> anyhow::Result<()> {
        let mut last_finalized_block = self
            .provider
            .get_block_by_number(Finalized, Full)
            .await?
            .unwrap()
            .header
            .number;

        loop {
            // Fetch the most recent finalized block
            let finalized_block = self
                .provider
                .get_block_by_number(Finalized, Full)
                .await?
                .unwrap()
                .header
                .number;

            if finalized_block > last_finalized_block {
                // Fetch logs for new blocks
                let filter = self
                    .filter
                    .clone()
                    .from_block(last_finalized_block - 64)
                    .to_block(finalized_block); // Up to the most recent finalized block

                let logs = self.provider.get_logs(&filter).await?;
                for log in logs {
                    let (event_data, match_id) = self.parser.parse_event(log.clone());

                    if !event_data.is_null() {
                        self.store_event(log, event_data, match_id).await;
                    }
                }

                // Update the last finalized block
                last_finalized_block = finalized_block;

                // Sleep for 20 seconds before polling again
                tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
            }
        }
    }

    async fn store_event(&self, log: Log, event_data: serde_json::Value, match_id: String) {
        if let Err(err) = self
            .db_client
            .insert_event(
                log.removed,
                &self.event_topic().to_string(),
                &self.event_kind(),
                event_data,
                match_id,
                log.block_number.unwrap_or_default() as i64,
                log.block_timestamp.unwrap_or_default() as i64,
                &log.transaction_hash.unwrap_or_default().to_string(),
                log.transaction_index.unwrap_or_default() as i32,
                log.log_index.unwrap_or_default() as i32,
            )
            .await
        {
            eprintln!("Failed to insert event into database: {}", err);
        }
    }
}

// Define Parsers for the events
#[derive(Serialize, Deserialize)]
struct BuyGasTicketsLog {
    blinded: Vec<Bytes>,
}

// Define Parsers for the events
#[derive(Serialize, Deserialize)]
struct BuyGasTicketsProcessed {
    blinded: Vec<Bytes>,
    blind_sigs: Vec<BlindedSignature>,
}

// Define Parsers for the events
#[derive(Serialize, Deserialize)]
struct BuyGasTicketsEvent {
    log_data: BuyGasTicketsLog,
    processed_data: BuyGasTicketsProcessed,
}

#[derive(Clone)]
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

    fn parse_event(&self, log: Log) -> (serde_json::Value, String) {
        match log.log_decode::<IStealthGasStation::BuyGasTickets>() {
            Ok(decoded_log) => {
                println!(
                    "[PARSE BuyGasTickets] :: {:?}",
                    log.transaction_hash.unwrap_or_default()
                );
                let blinded_messages = decoded_log.inner.blinded.clone();

                let log_data = BuyGasTicketsLog {
                    blinded: blinded_messages.clone(),
                };

                let (processed_blinded, processed_signed) =
                    self.signer.sign_blinded_messages_filtered(blinded_messages);
                let processed_ids = processed_blinded
                    .iter()
                    .map(|msg| FixedBytes::<32>::from_slice(&Sha256::digest(&msg)))
                    .collect::<Vec<FixedBytes<32>>>();
                let mut processed_blind_sigs = Vec::new();
                for i in 0..processed_signed.len() {
                    processed_blind_sigs.push(BlindedSignature {
                        id: FixedBytes::<32>::from_slice(processed_ids[i].as_ref()),
                        blind_sig: processed_signed[i].clone(),
                    });
                }

                let processed_data = BuyGasTicketsProcessed {
                    blinded: processed_blinded,
                    blind_sigs: processed_blind_sigs,
                };

                let event = BuyGasTicketsEvent {
                    log_data,
                    processed_data,
                };

                let match_id = compute_ids_hash(&processed_ids);
                (
                    serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
                    match_id,
                )
            }
            Err(_e) => {
                //eprintln!("Failed to decode BuyGasTickets event: {}", e);
                (serde_json::Value::Null, "".to_owned())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SendGasTicketsEventLog {
    ids: Vec<FixedBytes<32>>,
    signed: Vec<Bytes>,
}

#[derive(Serialize, Deserialize)]
struct SendGasTicketsEvent {
    log_data: SendGasTicketsEventLog,
}

#[derive(Clone)]
pub struct SendGasTicketsParser;

impl EventParser for SendGasTicketsParser {
    fn event_topic(&self) -> B256 {
        IStealthGasStation::SendGasTickets::SIGNATURE_HASH
    }

    fn event_kind(&self) -> String {
        "SendGasTickets".to_owned()
    }

    fn parse_event(&self, log: Log) -> (serde_json::Value, String) {
        match log.log_decode::<IStealthGasStation::SendGasTickets>() {
            Ok(decoded_log) => {
                println!(
                    "[PARSE SendGasTickets] :: {:?}",
                    log.transaction_hash.unwrap_or_default()
                );
                let match_id = compute_ids_hash(&decoded_log.inner.ids.clone());
                let log_data = SendGasTicketsEventLog {
                    ids: decoded_log.inner.ids.clone(),
                    signed: decoded_log.inner.signed.clone(),
                };
                let event = SendGasTicketsEvent { log_data };
                (
                    serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
                    match_id,
                )
            }
            Err(_e) => {
                //eprintln!("Failed to decode SendGasTickets event: {}", e);
                (serde_json::Value::Null, "".to_owned())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct NativeTransfersEventLog {
    amounts: Vec<U256>,
    targets: Vec<Address>,
    data: Bytes,
}

#[derive(Serialize, Deserialize)]
struct NativeTransfersEvent {
    log_data: NativeTransfersEventLog,
}

#[derive(Clone)]
pub struct NativeTransfersParser;

impl EventParser for NativeTransfersParser {
    fn event_topic(&self) -> B256 {
        IStealthGasStation::NativeTransfers::SIGNATURE_HASH
    }

    fn event_kind(&self) -> String {
        "NativeTransfers".to_owned()
    }

    fn parse_event(&self, log: Log) -> (serde_json::Value, String) {
        match log.log_decode::<IStealthGasStation::NativeTransfers>() {
            Ok(decoded_log) => {
                println!(
                    "[PARSE NativeTransfers] :: {:?}",
                    log.transaction_hash.unwrap_or_default()
                );
                let log_data = NativeTransfersEventLog {
                    amounts: decoded_log.inner.amounts.clone(),
                    targets: decoded_log.inner.targets.clone(),
                    data: decoded_log.inner.d.clone(),
                };
                let event = NativeTransfersEvent { log_data };
                (
                    serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
                    "".to_owned(),
                )
            }
            Err(_e) => {
                //eprintln!("Failed to decode NativeTransfers event: {}", e);
                (serde_json::Value::Null, "".to_owned())
            }
        }
    }
}
