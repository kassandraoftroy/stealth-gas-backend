use sqlx::{PgPool, Row};
use sqlx::types::chrono::{DateTime, Utc};
use serde_json::Value;

// Event states as an enum to prevent string errors
#[derive(Debug, PartialEq)]
pub enum EventState {
    Indexed,
    Pending,
    Included,
    Fulfilled,
    Discarded,
}

impl EventState {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventState::Indexed => "INDEXED",
            EventState::Pending => "PENDING",
            EventState::Included => "INCLUDED",
            EventState::Fulfilled => "FULFILLED",
            EventState::Discarded => "DISCARDED",
        }
    }
    pub fn from_str(state: &str) -> Self {
        match state {
            "INDEXED" => EventState::Indexed,
            "PENDING" => EventState::Pending,
            "INCLUDED" => EventState::Included,
            "FULFILLED" => EventState::Fulfilled,
            "DISCARDED" => EventState::Discarded,
            _ => EventState::Indexed // Default case
        }
    }
}

#[derive(Debug)]
pub struct BuyEventInfo {
    pub transaction_hash: String,
    pub log_index: i32,
    pub fulfill_tx_hash: String,
    pub match_id: String,
    pub event_state: EventState,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct BuyEventData {
    pub transaction_hash: String,
    pub log_index: i32,
    pub event_data: Value,
}

#[derive(Debug)]
pub struct SpendInfo {
    pub id: i32,
    pub tx_hash: String,
    pub spend_data: Value,
    pub spend_state: EventState,
    pub updated_at: DateTime<Utc>,
}

// Database operations trait
#[derive(Clone)]
pub struct DbClient {
    pub pool: PgPool,
}

impl DbClient {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // Event Operations
    pub async fn insert_event(
        &self,
        removed: bool,
        event_topic: &str,
        event_kind: &str,
        event_data: Value,
        match_id: String,
        block_number: i64,
        block_timestamp: i64,
        transaction_hash: &str,
        transaction_index: i32,
        log_index: i32,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO events (removed, event_topic, event_kind, event_state, event_data, match_id, 
                               block_number, block_timestamp, transaction_hash, transaction_index, log_index) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (transaction_hash, log_index)
             DO UPDATE SET
             removed = EXCLUDED.removed,
             block_number = EXCLUDED.block_number,
             block_timestamp = EXCLUDED.block_timestamp,
             transaction_index = EXCLUDED.transaction_index"
        )
        .bind(removed)
        .bind(event_topic)
        .bind(event_kind)
        .bind(EventState::Indexed.as_str())
        .bind(event_data)
        .bind(match_id)
        .bind(block_number)
        .bind(block_timestamp)
        .bind(transaction_hash)
        .bind(transaction_index)
        .bind(log_index)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to insert event: {}", e))?;

        Ok(())
    }

    pub async fn get_next_buy_event(&self) -> Result<Option<BuyEventData>, String> {
        sqlx::query(
            "SELECT transaction_hash, log_index, event_data FROM events 
             WHERE event_kind = 'BuyGasTickets' AND event_state = 'INDEXED' AND removed = false 
             ORDER BY updated_at ASC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await
        .map(|maybe_row| {
            maybe_row.map(|row| BuyEventData {
                transaction_hash: row.get("transaction_hash"),
                log_index: row.get("log_index"),
                event_data: row.get("event_data"),
            })
        })
        .map_err(|e| format!("Failed to fetch events: {}", e))
    }

    pub async fn get_next_spend(&self) -> Result<Option<SpendInfo>, String> {
        sqlx::query(
            "SELECT id, tx_hash, spend_data, spend_state, updated_at FROM spends WHERE spend_state = 'INDEXED' ORDER BY updated_at ASC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(|row| SpendInfo {
            id: row.get("id"),
            tx_hash: row.get("tx_hash"),
            spend_data: serde_json::from_value(row.get("spend_data")).unwrap(),
            spend_state: EventState::from_str(row.get("spend_state")),
            updated_at: row.get("updated_at"),
        }))
        .map_err(|e| format!("Failed to fetch spends: {}", e))
    }

    pub async fn update_event_state(
        &self,
        transaction_hash: &str,
        log_index: i32,
        state: EventState,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE events SET event_state = $1, updated_at = NOW() 
             WHERE transaction_hash = $2 AND log_index = $3"
        )
        .bind(state.as_str())
        .bind(transaction_hash)
        .bind(log_index)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update event state: {}", e))?;

        Ok(())
    }

    pub async fn update_event_tx_data(
        &self,
        transaction_hash: &str,
        log_index: i32,
        fulfill_tx_hash: &str,
        nonce: i64,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE events SET fulfill_tx_hash = $1, fulfill_tx_nonce = $2, updated_at = NOW() 
             WHERE transaction_hash = $3 AND log_index = $4"
        )
        .bind(fulfill_tx_hash)
        .bind(nonce)
        .bind(transaction_hash)
        .bind(log_index)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update fulfill tx: {}", e))?;

        Ok(())
    }

    pub async fn get_unfulfilled_buys(&self) -> Result<Vec<BuyEventInfo>, String> {
        sqlx::query(
            "SELECT transaction_hash, log_index, event_data, fulfill_tx_hash, fulfill_tx_nonce, 
                    match_id, event_state, updated_at 
             FROM events 
             WHERE event_kind = 'BuyGasTickets' AND event_state IN ('PENDING', 'INCLUDED', 'INDEXED') 
             AND removed = false"
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| BuyEventInfo {
                    transaction_hash: row.get("transaction_hash"),
                    log_index: row.get("log_index"),
                    fulfill_tx_hash: row.get("fulfill_tx_hash"),
                    match_id: row.get("match_id"),
                    event_state: EventState::from_str(row.get("event_state")),
                    updated_at: row.get("updated_at"),
                })
                .collect()
        })
        .map_err(|e| format!("Failed to fetch pending events: {}", e))
    }

    pub async fn get_unfulfilled_spends(&self) -> Result<Vec<SpendInfo>, String> {
        sqlx::query(
            "SELECT id, tx_hash, spend_state, spend_data, updated_at FROM spends WHERE spend_state IN ('PENDING', 'INCLUDED', 'INDEXED')"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to fetch pending events: {}", e))
        .map(|rows| {
            rows.into_iter().map(|row| SpendInfo {
                id: row.get("id"),
                tx_hash: row.get("tx_hash"),
                spend_data: row.get("spend_data"),
                spend_state: EventState::from_str(row.get("spend_state")),
                updated_at: row.get("updated_at"),
            }).collect()
        })
    }

    // Ticket Operations
    pub async fn check_ticket_used(&self, msg_id: &str) -> Result<bool, String> {
        sqlx::query!(
            "SELECT COUNT(*) FROM tickets WHERE message_id = $1",
            msg_id
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| row.count.unwrap_or(0) > 0)
        .map_err(|e| format!("Failed to check ticket usage: {}", e))
    }

    pub async fn insert_new_ticket(&self, msg_id: &str, sig: &str) -> Result<(), String> {
        sqlx::query!(
            "INSERT INTO tickets (message_id, sig) VALUES ($1, $2)",
            msg_id,
            sig
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to store ticket: {}", e))?;

        Ok(())
    }

    pub async fn delete_ticket(&self, msg_id: &str) -> Result<(), String> {
        sqlx::query!(
            "DELETE FROM tickets WHERE message_id = $1",
            msg_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to delete ticket: {}", e))?;

        Ok(())
    }

    pub async fn update_ticket_spend_id(&self, spend_id: i32, msg_id: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE tickets SET spend_id = $1, updated_at = NOW() 
             WHERE message_id = $2"
        )
        .bind(spend_id)
        .bind(msg_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update ticket state: {}", e))?;

        Ok(())
    }

    pub async fn get_msg_ids_from_spend_id(&self, spend_id: i32) -> Result<Vec<String>, String> {
        sqlx::query(
            "SELECT message_id FROM tickets WHERE spend_id = $1"
        )
        .bind(spend_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.iter().map(|row| row.get("message_id")).collect())
        .map_err(|e| format!("Failed to fetch msg ids: {}", e))
    }

    pub async fn insert_new_spend(&self, spends: Value, tx_hash: &str, tx_nonce: i32) -> Result<i32, String> {
        sqlx::query!(
            "INSERT INTO spends (spend_state, spend_data, tx_hash, tx_nonce) VALUES ($1, $2, $3, $4) RETURNING id",
            EventState::Pending.as_str(),
            spends,
            tx_hash,
            tx_nonce
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| row.id)
        .map_err(|e| format!("Failed to store spend: {}", e))
    }

    pub async fn update_spend_state(
        &self,
        row_id: i32,
        state: EventState,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE spends SET spend_state = $1, updated_at = NOW() 
             WHERE id = $2"
        )
        .bind(state.as_str())
        .bind(row_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update used ticket state: {}", e))?;

        Ok(())
    }

    pub async fn check_matching_send_gas_tickets(&self, match_id: &str) -> Result<bool, String> {
        sqlx::query(
            "SELECT transaction_hash FROM events 
             WHERE event_kind = 'SendGasTickets' AND match_id = $1 AND removed = false"
        )
        .bind(match_id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.is_some())
        .map_err(|e| format!("Failed to check matching SendGasTickets event: {}", e))
    }

    pub async fn check_matching_native_transfer(&self, tx_hash: &str) -> Result<bool, String> {
        sqlx::query(
            "SELECT transaction_hash FROM events WHERE event_kind = 'NativeTransfers' AND transaction_hash = $1 AND removed = false"
        )
        .bind(tx_hash)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.is_some())
        .map_err(|e| format!("Failed to check matching spend tx hash: {}", e))
    }

    pub async fn update_spend_tx_data(&self, spend_id: i32, tx_hash: &str, tx_nonce: i64) -> Result<(), String> {
        sqlx::query(
            "UPDATE spends SET tx_hash = $1, tx_nonce = $2, updated_at = NOW() 
             WHERE id = $3"
        )
        .bind(tx_hash)
        .bind(tx_nonce)
        .bind(spend_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update spend tx data: {}", e))?;
        
        Ok(())
    }
}
