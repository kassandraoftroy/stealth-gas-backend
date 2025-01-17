use crate::gas_station_helper::{IStealthGasStationInstance, StealthGasStationHelper};
use crate::sql::DbClient;
use alloy::{
    network::{Ethereum, EthereumWallet, TransactionBuilder},
    primitives::{Address, FixedBytes, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, RootProvider,
    },
    pubsub::PubSubFrontend,
    rpc::types::TransactionRequest,
};
use eth_stealth_gas_tickets::{SignedTicket, TicketsVerifier};
use rocket::{get, post, routes, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use rocket::config::{Config, TlsConfig};

type CombinedFiller = JoinFill<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    WalletFiller<EthereumWallet>,
>;
type AppProvider =
    Arc<FillProvider<CombinedFiller, RootProvider<PubSubFrontend>, PubSubFrontend, Ethereum>>;

// Struct to represent a spend request
#[derive(Serialize, Deserialize)]
pub struct SpendRequest {
    pub signatures: Vec<SignedTicket>,
    pub spends: Vec<Spend>,
}

// Struct to represent an individual spend
#[derive(Serialize, Deserialize, Clone, Debug)]
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
    pub signer_address: Address,
    pub provider: AppProvider,
    pub verifier: Arc<TicketsVerifier>,
    pub db_client: DbClient,
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

#[get("/chainId")]
async fn chain_id(state: &State<AppState>) -> Json<u64> {
    Json(state.provider.get_chain_id().await.unwrap())
}

// Route: POST /validate
#[post("/validate", format = "json", data = "<signatures>")]
async fn validate_tickets(
    state: &State<AppState>,
    signatures: Json<Vec<SignedTicket>>,
) -> Json<Vec<bool>> {
    let options = state.verifier.get_options();
    let mut results = Vec::new();

    for ticket in signatures.into_inner() {
        match state.verifier.verify_signed_ticket(&ticket, &options) {
            Ok(_) => {}
            Err(_) => {
                results.push(false);
                continue;
            }
        }

        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(ticket.msg.to_vec()),
            hex::encode(ticket.msg_randomizer.as_slice())
        );

        match state.db_client.check_ticket_used(&msg_id).await {
            Ok(is_used) => results.push(!is_used),
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
    let total_amount: U256 = spend_request.spends.iter().map(|spend| spend.amount).sum();

    // check amounts
    let max_amount = U256::from(spend_request.signatures.len()) * state.ticket_cost;
    let mut spends = spend_request.spends.clone();
    if total_amount > max_amount {
        return Err("Invalid total spend amount".to_string());
    } else if total_amount < max_amount {
        spends.push(Spend {
            amount: max_amount - total_amount,
            receiver: state.signer_address,
        });
    }

    let options = state.verifier.get_options();
    for sig in &spend_request.signatures {
        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(sig.msg.to_vec()),
            hex::encode(sig.msg_randomizer.as_slice())
        );

        if state.db_client.check_ticket_used(&msg_id).await? {
            return Err("Replay detected".to_string());
        }
        if state.verifier.verify_signed_ticket(sig, &options).is_err() {
            return Err("Invalid signature".to_string());
        }
    }

    let contract = IStealthGasStationInstance::init(state.contract_address, state.provider.clone());

    let (amounts, receivers): (Vec<U256>, Vec<Address>) = spends
        .clone()
        .into_iter()
        .map(|spend| (spend.amount, spend.receiver))
        .unzip();

    println!("amounts: {:?}", amounts);
    println!("receivers: {:?}", receivers);
    let payload = contract.payload_send_gas(amounts, receivers);
    println!("payload: {:?}", payload);
    let nonce = state
        .provider
        .get_transaction_count(state.signer_address)
        .await
        .map_err(|e| e.to_string())?;
    let mut tx_request = TransactionRequest::default()
        .with_to(state.contract_address)
        .with_nonce(nonce)
        .with_input(payload.data)
        .with_max_fee_per_gas(500000000000)
        .with_max_priority_fee_per_gas(1000000000);
    println!("SIMULATING");
    match state.provider.estimate_gas(&tx_request).await {
        Ok(gas_limit) => {
            println!("SIMULATION SUCCESS");
            if gas_limit < 1000000 {
                println!("Gas limit: {}", gas_limit);
                tx_request = tx_request.with_gas_limit(gas_limit + 25000);
            } else {
                return Err("Tx exceeds gas limit (1 million)".to_string());
            }
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }

    for sig in &spend_request.signatures {
        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(sig.msg.to_vec()),
            hex::encode(sig.msg_randomizer.as_slice())
        );

        state
            .db_client
            .insert_new_ticket(
                &msg_id,
                &format!("0x{}", hex::encode(sig.finalized_sig.to_vec())),
            )
            .await?;
    }

    let pending = state
        .provider
        .send_transaction(tx_request)
        .await
        .map_err(|e| e.to_string())?;

    let tx_hash = *pending.tx_hash();
    let result = state
        .db_client
        .insert_new_spend(
            serde_json::to_value(spends.clone()).unwrap(),
            &format!("0x{}", hex::encode(tx_hash.to_vec())),
            nonce as i32,
        )
        .await?;
    for sig in &spend_request.signatures {
        let msg_id = format!(
            "0x{}0x{}",
            hex::encode(sig.msg.to_vec()),
            hex::encode(sig.msg_randomizer.as_slice())
        );
        state
            .db_client
            .update_ticket_spend_id(result, &msg_id)
            .await?;
    }

    Ok(Json(SpendReceipt {
        spends: spends,
        transaction_hash: tx_hash,
    }))
}

// Launch the Rocket server
pub async fn start_http_server(
    ticket_cost: U256,
    contract_address: Address,
    signer_address: Address,
    provider: AppProvider,
    verifier: Arc<TicketsVerifier>,
    db_client: DbClient,
) {
    let state = AppState {
        ticket_cost,
        contract_address,
        signer_address,
        provider,
        verifier,
        db_client,
    };

        rocket::build()
        .configure(rocket::Config {
            address: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
            port: 8000,
            ..Default::default()
        })
        .manage(state)
        .mount(
            "/",
            routes![hello, contract_address, chain_id, validate_tickets, redeem],
        )
        .launch()
        .await
        .expect("Failed to launch Rocket server");
}

pub async fn start_http_server_with_ssl(
    ticket_cost: U256,
    contract_address: Address,
    signer_address: Address,
    provider: AppProvider,
    verifier: Arc<TicketsVerifier>,
    db_client: DbClient,
    tls_cert_path: String,
    tls_key_path: String,
) {
    let state = AppState {
        ticket_cost,
        contract_address,
        signer_address,
        provider,
        verifier,
        db_client,
    };

    // Configure Rocket for HTTPS
    let config = Config::figment()
        .merge(("port", 8000))
        .merge(("address", "0.0.0.0"))
        .merge(("tls", TlsConfig::from_paths(&tls_cert_path, &tls_key_path)));

    rocket::custom(config)
        .manage(state)
        .mount(
            "/",
            routes![hello, contract_address, chain_id, validate_tickets, redeem],
        )
        .launch()
        .await
        .expect("Failed to launch Rocket server");
}
