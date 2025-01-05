use rocket::{get, post, routes, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use alloy::{
    network::{TransactionBuilder, Ethereum, EthereumWallet},
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{fillers::{FillProvider, JoinFill, GasFiller, ChainIdFiller, NonceFiller, WalletFiller, BlobGasFiller}, RootProvider, Identity, Provider},
    pubsub::PubSubFrontend,
    rpc::types::TransactionRequest
};
use eth_stealth_gas_tickets::{CoordinatorPubKey, SignedTicket};
use sqlx::PgPool;
use std::sync::Arc;
use crate::gas_station_helper::{StealthGasStationHelper, IStealthGasStationInstance};

type CombinedFiller = JoinFill<
    JoinFill<Identity, JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>>,
    WalletFiller<EthereumWallet>
>;
type AppProvider = Arc<FillProvider<
    CombinedFiller,
    RootProvider<PubSubFrontend>,
    PubSubFrontend,
    Ethereum
>>;

// Struct to represent a signed unblinded signature
#[derive(Serialize, Deserialize)]
pub struct UnblindedTicket {
    pub msg: Bytes,
    pub msg_randomizer: FixedBytes<32>,
    pub signature: Bytes,
}

// Struct to represent a spend request
#[derive(Serialize, Deserialize)]
pub struct SpendRequest {
    pub signatures: Vec<UnblindedTicket>,
    pub spends: Vec<Spend>,
}

// Struct to represent an individual spend
#[derive(Serialize, Deserialize, Clone)]
pub struct Spend {
    pub amount: U256,
    pub receiver: Address,
}

// Struct to represent a spend receipt
#[derive(Serialize, Deserialize)]
pub struct SpendReceipt {
    pub spends: Vec<Spend>,
    pub transaction_hash: FixedBytes<32>,
}

// Shared application state
pub struct AppState {
    pub ticket_cost: U256,
    pub contract_address: Address,
    pub provider: AppProvider,
    pub verifier: Arc<CoordinatorPubKey>,
    pub db_pool: PgPool,
}

// Route: GET /hello (Health check)
#[get("/hello")]
fn hello() -> &'static str {
    "OK"
}

// Route: GET /contract
#[get("/contract")]
fn contract_address(state: &State<AppState>) -> Json<Address> {
    Json(state.contract_address)
}

// Route: POST /validate
#[post("/validate", format = "json", data = "<signatures>")]
async fn validate_tickets(
    state: &State<AppState>,
    signatures: Json<Vec<UnblindedTicket>>,
) -> Json<Vec<bool>> {
    let db_pool = &state.db_pool;
    let options = state.verifier.get_options();
    let mut results = Vec::new();

    for sig in signatures.into_inner() {
        let signed_ticket = SignedTicket {
            msg: sig.msg.clone(),
            msg_randomizer: sig.msg_randomizer,
            finalized_sig: sig.signature,
            id: sig.msg_randomizer,
        };

        match state.verifier.verify_signed_ticket(signed_ticket, &options) {
            Ok(_) => {}
            Err(_) => {
                results.push(false);
                continue;
            }
        }

        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(sig.msg.to_vec()),
            hex::encode(sig.msg_randomizer.as_slice())
        );

        let query = sqlx::query!(
            "SELECT COUNT(*) FROM unblinded WHERE message_id = $1",
            msg_id
        )
        .fetch_one(db_pool)
        .await;

        match query {
            Ok(row) => results.push(row.count == None || row.count.unwrap() == 0),
            Err(_) => results.push(false),
        }
    }
    Json(results)
}

// Route: POST /redeem
#[post("/redeem", format = "json", data = "<spend_request>")]
async fn redeem(
    state: &State<AppState>,
    spend_request: Json<SpendRequest>,
) -> Result<Json<SpendReceipt>, String> {
    let db_pool = &state.db_pool;
    let total_amount: U256 = spend_request.spends.iter().map(|spend| spend.amount).sum();

    if total_amount != U256::from(spend_request.signatures.len()) * state.ticket_cost {
        return Err("Invalid total spend amount".to_string());
    }

    let options = state.verifier.get_options();
    for sig in &spend_request.signatures {
        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(sig.msg.to_vec()),
            hex::encode(sig.msg_randomizer.as_slice())
        );

        let query = sqlx::query!(
            "SELECT COUNT(*) FROM unblinded WHERE message_id = $1",
            msg_id
        )
        .fetch_one(db_pool)
        .await;

        if let Ok(row) = query {
            if !row.count.is_none() && row.count.unwrap() > 0 {
                return Err("Replay detected".to_string());
            }
        }

        sqlx::query!(
            "INSERT INTO unblinded (message_id, sig, sig_state) VALUES ($1, $2, $3)",
            msg_id,
            format!("0x{}", hex::encode(sig.signature.to_vec())),
            "PENDING"
        )
        .execute(db_pool)
        .await
        .map_err(|e| e.to_string())?;

        let signed_ticket = SignedTicket {
            msg: sig.msg.clone(),
            msg_randomizer: sig.msg_randomizer,
            finalized_sig: sig.signature.clone(),
            id: sig.msg_randomizer,
        };

        if state.verifier.verify_signed_ticket(signed_ticket, &options).is_err() {
            return Err("Invalid signature".to_string());
        }
    }

    let tx_hash = do_spend_tx(
        state.contract_address,
        state.provider.clone(),
        spend_request.spends.clone(),
    )
    .await?;

    Ok(Json(SpendReceipt {
        spends: spend_request.spends.clone(),
        transaction_hash: tx_hash,
    }))
}

// Helper function to perform the spend transaction
async fn do_spend_tx(
    contract_address: Address,
    provider: AppProvider,
    spends: Vec<Spend>,
) -> Result<FixedBytes<32>, String> {
    let contract = IStealthGasStationInstance::init(contract_address, provider.clone());

    let (amounts, receivers): (Vec<U256>, Vec<Address>) =
        spends.into_iter().map(|spend| (spend.amount, spend.receiver)).unzip();

    let payload = contract.payload_send_gas(amounts, receivers);

    let mut tx_request = TransactionRequest::default()
        .with_to(contract_address)
        .with_input(payload.data)
        .with_value(payload.value)
        .with_max_fee_per_gas(500000000000)
        .with_max_priority_fee_per_gas(1000000000);

    match provider.estimate_gas(&tx_request).await {
        Ok(gas_limit) => {
            tx_request = tx_request.with_gas_limit(gas_limit + 25000);
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }

    let pending = provider
        .send_transaction(tx_request)
        .await
        .map_err(|e| e.to_string())?;

    Ok(*pending.tx_hash())
}

// Launch the Rocket server
pub async fn start_http_server(
    ticket_cost: U256,
    contract_address: Address,
    provider: AppProvider,
    verifier: Arc<CoordinatorPubKey>,
    db_pool: PgPool,
) {
    let state = AppState {
        ticket_cost,
        contract_address,
        provider,
        verifier,
        db_pool,
    };

    rocket::build()
        .manage(state)
        .mount("/", routes![hello, contract_address, validate_tickets, redeem])
        .launch()
        .await
        .expect("Failed to launch Rocket server");
}
