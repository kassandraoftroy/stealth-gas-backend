use alloy::{
    network::{TransactionBuilder, Network},
    primitives::{Address, FixedBytes, U256},
    providers::{Provider, PendingTransactionBuilder},
    pubsub::PubSubFrontend,
    rpc::types::TransactionRequest,
    transports::Transport,
};
use crate::gas_station_helper::{StealthGasStationHelper, IStealthGasStationInstance};
use eth_stealth_gas_tickets::BlindedSignature;
use std::sync::Arc;
use sqlx::types::chrono::Utc;
use crate::sql::{DbClient, EventState};
use crate::http_server::Spend;

pub fn get_hash_from_builder<T: Transport + Clone, N: Network>(builder: &PendingTransactionBuilder<T, N>) -> FixedBytes<32> {
    *builder.tx_hash()
}

pub struct Fulfiller<P: Provider<PubSubFrontend>> {
    pub db_client: DbClient,
    pub contract_address: Address,
    pub signer_address: Address,
    pub provider: Arc<P>,
}

impl<P: Provider<PubSubFrontend> + 'static> Fulfiller<P> {
    pub fn new(
        db_client: DbClient,
        contract_address: Address,
        signer_address: Address,
        provider: Arc<P>,
    ) -> Self {
        Self {
            db_client,
            contract_address,
            signer_address,
            provider,
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        loop {
            if let Err(e) = self.check_and_sync_buy_events().await {
                eprintln!("Error checking pending/included buys: {}", e);
            }
            if let Err(e) = self.process_next_buy_event().await {
                eprintln!("Error processing buy: {}", e);
            }
            if let Err(e) = self.check_and_sync_spends().await {
                eprintln!("Error checking pending/included spends: {}", e);
            }
            if let Err(e) = self.process_next_spend().await {
                eprintln!("Error processing spend: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        }
    }

    async fn process_next_buy_event(&self) -> Result<(), String> {
        if let Some(event) = self.db_client.get_next_buy_event().await? {
            let transaction_hash = event.transaction_hash;
            let log_index = event.log_index;
            let event_data = event.event_data;

            let blind_sigs: Vec<BlindedSignature> = serde_json::from_value(event_data["processed_data"]["blind_sigs"].clone())
                .map_err(|e| format!("Failed to parse blind signatures: {}", e))?;
            
            if blind_sigs.is_empty() {
                self.db_client.update_event_state(&transaction_hash, log_index, EventState::Discarded).await?;
                return Ok(());
            }

            self.db_client.update_event_state(&transaction_hash, log_index, EventState::Pending).await?;

            self.dispatch_send_gas_tickets(&transaction_hash, log_index, blind_sigs)
                .await.map_err(|e| format!("Error dispatching sendGasTickets: {}", e))?;
        }
        Ok(())
    }

    async fn dispatch_send_gas_tickets(
        &self,
        transaction_hash: &str,
        log_index: i32,
        blind_sigs: Vec<BlindedSignature>,
    ) -> Result<(), String> {
        let contract = IStealthGasStationInstance::init(self.contract_address, self.provider.clone());
        let payload = contract.payload_send_gas_tickets(blind_sigs);

        let nonce = self.provider.get_transaction_count(self.signer_address).await.map_err(|e| e.to_string())?;
        let mut tx_request = TransactionRequest::default()
            .with_from(self.signer_address)
            .with_to(self.contract_address)
            .with_input(payload.data)
            .with_value(payload.value)
            .with_nonce(nonce)
            .with_max_fee_per_gas(500000000000)
            .with_max_priority_fee_per_gas(1000000000);

        match self.provider.estimate_gas(&tx_request).await {
            Ok(gas_limit) => {
                tx_request = tx_request.with_gas_limit(gas_limit + 25000);
            }
            Err(e) => {
                self.db_client.update_event_state(transaction_hash, log_index, EventState::Indexed).await?;

                return Err(format!("Failed to estimate gas: {}", e));
            }
        }

        println!("[TX attempt] for event: {}", transaction_hash);
        let builder = self
            .provider
            .send_transaction(tx_request)
            .await
            .map_err(|e| e.to_string())?;

        let tx_hash = format!("0x{}", hex::encode(get_hash_from_builder(&builder)));

        self.db_client.update_event_tx_data(transaction_hash, log_index, &tx_hash, nonce as i64).await?;

        Ok(())
    }

    async fn process_next_spend(&self) -> Result<(), String> {
        if let Some(spend) = self.db_client.get_next_spend().await? {
            let contract = IStealthGasStationInstance::init(self.contract_address, self.provider.clone());
            let (amounts, receivers): (Vec<U256>, Vec<Address>) =
                serde_json::from_value::<Vec<Spend>>(spend.spend_data.clone())
                    .unwrap()
                    .into_iter()
                    .map(|spend| (spend.amount, spend.receiver))
                    .unzip();

            self.db_client.update_spend_state(spend.id, EventState::Pending).await?;
            let payload = contract.payload_send_gas(amounts, receivers);

            let nonce = self.provider.get_transaction_count(self.signer_address).await.map_err(|e| e.to_string())?;
            let mut tx_request = TransactionRequest::default()
                .with_from(self.signer_address)
                .with_to(self.contract_address)
                .with_input(payload.data)
                .with_value(payload.value)
                .with_nonce(nonce)
                .with_max_fee_per_gas(500000000000)
                .with_max_priority_fee_per_gas(1000000000);

            match self.provider.estimate_gas(&tx_request).await {
                Ok(gas_limit) => {
                    tx_request = tx_request.with_gas_limit(gas_limit + 25000);
                }
                Err(e) => {
                    return Err(format!("Failed to estimate gas: {}", e));
                }
            }

            println!("[TX attempt] for spend: {}", spend.id);
            let builder = self
                .provider
                .send_transaction(tx_request)
                .await
                .map_err(|e| e.to_string())?;

            let tx_hash = format!("0x{}", hex::encode(get_hash_from_builder(&builder)));
            self.db_client.update_spend_tx_data(spend.id, &tx_hash, nonce as i64).await?;
        }
        Ok(())
    }

    async fn check_and_sync_buy_events(&self) -> Result<(), String> {
        let pending_events = self.db_client.get_unfulfilled_buys().await?;

        for event in pending_events {
            let transaction_hash = event.transaction_hash;
            let log_index = event.log_index;
            let match_id = event.match_id;
            let updated_at = event.updated_at;
            let fulfill_tx_hash = event.fulfill_tx_hash;
            let event_state = event.event_state;

            let now = Utc::now();
            let elapsed_time = now.signed_duration_since(updated_at);

            if !fulfill_tx_hash.is_empty() && (event_state == EventState::Pending || 
                (event_state == EventState::Included && elapsed_time.num_minutes() > 29)) {
                let fulfill_tx_hash_bytes: FixedBytes<32> = FixedBytes::from_slice(hex::decode(fulfill_tx_hash.replace("0x", "")).unwrap_or_default().as_slice());
                let mut state = EventState::Pending;
                match self.provider.get_transaction_receipt(fulfill_tx_hash_bytes).await {
                    Ok(receipt) => {
                        if receipt.is_some() {
                            if receipt.unwrap().status() {
                                state = EventState::Included;
                            } else {
                                state = EventState::Indexed;
                            }
                        }
                    },
                    Err(e) => {
                        println!("[INFO]Error finding tx receipt: {:?}", e);
                    }
                }
                if state != event_state {
                    println!("[PENDING TX] event: {}, updating state: {} -> {}", 
                        transaction_hash, event_state.as_str(), state.as_str());
                    self.db_client.update_event_state(&transaction_hash, log_index, state).await?;

                    continue;
                }
            }

            if self.db_client.check_matching_send_gas_tickets(&match_id).await? {
                println!("[FULFILLED BUY]: {}", transaction_hash);
                self.db_client.update_event_state(&transaction_hash, log_index, EventState::Fulfilled).await?;
            } else if elapsed_time.num_minutes() > 29 && event_state == EventState::Pending {
                println!("[RETURN BUY TO INDEXED]: {}", transaction_hash);
                self.db_client.update_event_state(&transaction_hash, log_index, EventState::Indexed).await?;
            }
        }

        Ok(())
    }

    async fn check_and_sync_spends(&self) -> Result<(), String> {
        let empty_msg_ids = self.db_client.get_msg_ids_from_spend_id(0).await?;
        for msg_id in empty_msg_ids {
            self.db_client.delete_ticket(&msg_id).await?;
        }

        let pending_spends = self.db_client.get_unfulfilled_spends().await?;
        let now = Utc::now();

        for spend in pending_spends {
            if self.db_client.check_matching_native_transfer(&spend.tx_hash).await? {
                println!("[FULFILLED SPEND] spend: {}, tx: {}", spend.id, spend.tx_hash);
                self.db_client.update_spend_state(spend.id, EventState::Fulfilled).await?;

                continue;
            }
            let elapsed_time = now.signed_duration_since(spend.updated_at);
            if spend.spend_state == EventState::Pending || 
                (spend.spend_state == EventState::Included && elapsed_time.num_minutes() > 29) {
                let tx_hash_bytes: FixedBytes<32> = FixedBytes::from_slice(hex::decode(spend.tx_hash.replace("0x", "")).unwrap_or_default().as_slice());
                let mut state = EventState::Pending;
                match self.provider.get_transaction_receipt(tx_hash_bytes).await {
                    Ok(receipt) => {
                        if receipt.is_some() {
                            if receipt.unwrap().status() {
                                state = EventState::Included;
                            } else {
                                state = EventState::Indexed;
                            }
                        }
                    },
                    Err(e) => {
                        println!("[INFO] Error finding tx receipt: {:?}", e);
                    }
                }
                if state != spend.spend_state {
                    println!("[PENDING SPEND TX] spend: {}, updating state: {} -> {}", 
                        spend.id, spend.spend_state.as_str(), state.as_str());
                    self.db_client.update_spend_state(spend.id, state).await?;

                    continue;
                }
            }
            if elapsed_time.num_minutes() > 29 && spend.spend_state == EventState::Pending {
                println!("[RETURN SPEND TO INDEXED]: {}", spend.id);
                self.db_client.update_spend_state(spend.id, EventState::Indexed).await?;

                continue;
            }

        }

        Ok(())
    }
}
