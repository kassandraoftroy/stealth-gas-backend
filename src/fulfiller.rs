use alloy::{
    network::TransactionBuilder,
    primitives::Address,
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::TransactionRequest
};
use crate::gas_station_helper::{StealthGasStationHelper, IStealthGasStationInstance};
use eth_stealth_gas_tickets::BlindedSignature;
use sqlx::PgPool;
use serde_json::Value;
use std::sync::Arc;
use sqlx::Row;
use sqlx::types::chrono::{DateTime, Utc};

pub struct Fulfiller<P: Provider<PubSubFrontend>> {
    pub db_pool: PgPool,
    pub contract_address: Address,
    pub signer_address: Address,
    pub provider: Arc<P>,
}

impl<P: Provider<PubSubFrontend> + 'static> Fulfiller<P> {
    pub fn new(
        db_pool: PgPool,
        contract_address: Address,
        signer_address: Address,
        provider: Arc<P>,
    ) -> Self {
        Self {
            db_pool,
            contract_address,
            signer_address,
            provider,
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        loop {
            if let Err(e) = self.check_pending_and_included_events().await {
                eprintln!("Error checking pending/included events: {}", e);
            }
            if let Err(e) = self.process_next_event().await {
                eprintln!("Error processing event: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    async fn process_next_event(&self) -> Result<(), String> {
        let row = sqlx::query(
            "SELECT transaction_hash, log_index, event_data, retry FROM events 
             WHERE event_kind = $1 AND event_state = 'INDEXED' AND removed = false 
             ORDER BY updated_at ASC LIMIT 1",
        )
        .bind("BuyGasTickets")
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

        if let Some(row) = row {
            let transaction_hash: String = row.get("transaction_hash");
            let log_index: i32 = row.get("log_index");
            let event_data: Value = row.get("event_data");
            let retry: i32 = row.get("retry");

            let blind_sigs: Vec<BlindedSignature> = serde_json::from_value(event_data["processed_data"]["blind_sigs"].clone())
                .map_err(|e| format!("Failed to parse blind signatures: {}", e))?;
            
            if blind_sigs.is_empty() || retry > 99 {
                sqlx::query(
                    "UPDATE events SET event_state = 'DISCARDED', updated_at = NOW() 
                     WHERE transaction_hash = $1 AND log_index = $2",
                )
                .bind(&transaction_hash)
                .bind(log_index)
                .execute(&self.db_pool)
                .await
                .map_err(|e| format!("Failed to update event state: {}", e))?;
                return Ok(());
            }

            sqlx::query(
                "UPDATE events SET event_state = 'PENDING', updated_at = NOW() 
                 WHERE transaction_hash = $1 AND log_index = $2",
            )
            .bind(&transaction_hash)
            .bind(log_index)
            .execute(&self.db_pool)
            .await
            .map_err(|e| format!("Failed to update event state: {}", e))?;

            if let Err(e) = self
                .dispatch_send_gas_tickets(&transaction_hash, log_index, retry + 1, blind_sigs)
                .await
            {
                eprintln!("Error dispatching sendGasTickets: {}", e);
            }
        }
        Ok(())
    }

    async fn dispatch_send_gas_tickets(
        &self,
        transaction_hash: &str,
        log_index: i32,
        retry: i32,
        blind_sigs: Vec<BlindedSignature>,
    ) -> Result<(), String> {
        let contract = IStealthGasStationInstance::init(self.contract_address, self.provider.clone());
        let payload = contract.payload_send_gas_tickets(blind_sigs);

        let mut tx_request = TransactionRequest::default()
            .with_from(self.signer_address)
            .with_to(self.contract_address)
            .with_input(payload.data)
            .with_value(payload.value)
            .with_max_fee_per_gas(500000000000)
            .with_max_priority_fee_per_gas(1000000000);

        match self.provider.estimate_gas(&tx_request).await {
            Ok(gas_limit) => {
                tx_request = tx_request.with_gas_limit(gas_limit + 25000);
            }
            Err(e) => {
                sqlx::query(
                    "UPDATE events SET event_state = 'INDEXED', retry = $3, updated_at = NOW() 
                     WHERE transaction_hash = $1 AND log_index = $2",
                )
                .bind(transaction_hash)
                .bind(log_index)
                .bind(retry)
                .execute(&self.db_pool)
                .await
                .map_err(|ee| format!("Failed to update event state: {}", ee))?;

                return Err(format!("Failed to estimate gas: {}", e));
            }
        }

        println!("[TX attempt]: {:?}", transaction_hash);
        let tx_hash = self
            .provider
            .send_transaction(tx_request)
            .await
            .map_err(|e| e.to_string())?
            .with_required_confirmations(2)
            .with_timeout(Some(std::time::Duration::from_secs(120)))
            .watch()
            .await
            .map_err(|e| e.to_string())?;

        let receipt = self.provider.get_transaction_receipt(tx_hash).await.map_err(|e| e.to_string())?;
        match receipt {
            Some(receipt) => {
                if !receipt.status() {
                    sqlx::query(
                        "UPDATE events SET event_state = 'INDEXED', retry = $3, updated_at = NOW() 
                    WHERE transaction_hash = $1 AND log_index = $2",
                    )
                    .bind(transaction_hash)
                    .bind(log_index)
                    .bind(retry)
                    .execute(&self.db_pool)
                    .await
                    .map_err(|e| format!("Failed to update event state: {}", e))?;

                    return Err("Transaction reverted onchain".to_string());
                }
            }
            None => {
                return Err("Transaction not found".to_string());
            }
        }

        sqlx::query(
            "UPDATE events SET event_state = 'INCLUDED', updated_at = NOW() 
             WHERE transaction_hash = $1 AND log_index = $2",
        )
        .bind(transaction_hash)
        .bind(log_index)
        .execute(&self.db_pool)
        .await
        .map_err(|e| format!("Failed to update event state: {}", e))?;

        println!("[TX included]: {} (hash: {:?})", transaction_hash, tx_hash);

        Ok(())
    }

    async fn check_pending_and_included_events(&self) -> Result<(), String> {
        let rows = sqlx::query(
            "SELECT transaction_hash, log_index, event_data, match_id, updated_at FROM events 
             WHERE event_kind = $1 AND event_state IN ('PENDING', 'INCLUDED', 'INDEXED') AND removed = false",
        )
        .bind("BuyGasTickets")
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| format!("Failed to fetch pending/included events: {}", e))?;

        for row in rows {
            let transaction_hash: String = row.get("transaction_hash");
            let log_index: i32 = row.get("log_index");
            let match_id: String = row.get("match_id");
            let updated_at: DateTime<Utc> = row.get("updated_at");

            let matching_event = sqlx::query(
                "SELECT transaction_hash, log_index FROM events 
                 WHERE event_kind = 'SendGasTickets' 
                 AND match_id = $1",
            )
            .bind(&match_id)
            .fetch_optional(&self.db_pool)
            .await
            .map_err(|e| format!("Failed to check matching SendGasTickets event: {}", e))?;

            if matching_event.is_some() {
                println!("[FULFILLED]: {}", transaction_hash);
                sqlx::query(
                    "UPDATE events SET event_state = 'FULFILLED', updated_at = NOW() 
                     WHERE transaction_hash = $1 AND log_index = $2",
                )
                .bind(transaction_hash)
                .bind(log_index)
                .execute(&self.db_pool)
                .await
                .map_err(|e| format!("Failed to fulfill event: {}", e))?;
            } else {
                println!("[NOT FULFILLED]: {}", transaction_hash);
                let now = Utc::now();
                let elapsed_time = now.signed_duration_since(updated_at);

                if elapsed_time.num_minutes() > 25 {
                    println!("[RETURNED TO INDEXED]: {}", transaction_hash);
                    sqlx::query(
                        "UPDATE events SET event_state = 'INDEXED', updated_at = NOW() 
                         WHERE transaction_hash = $1 AND log_index = $2",
                    )
                    .bind(transaction_hash)
                    .bind(log_index)
                    .execute(&self.db_pool)
                    .await
                    .map_err(|e| format!("Failed to revert event state: {}", e))?;
                }
            }
        }

        Ok(())
    }
}
