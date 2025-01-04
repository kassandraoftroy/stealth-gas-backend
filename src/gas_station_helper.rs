use alloy::{
    primitives::{Bytes, FixedBytes, U256, Address},
    providers::Provider,
    sol,
    transports::Transport,
};
use serde::Serialize;
use crate::types::BlindedSignature;

sol! {
    #[derive(Debug, Serialize)]
    #[sol(rpc)]
    interface IStealthGasStation {
        function sendGasTickets(bytes32[] calldata ids, bytes[] calldata signed) external;
    }
}

pub use IStealthGasStation::IStealthGasStationInstance;

pub struct StealthGasPayload {
    pub target: Address,
    pub data: Bytes,
    pub value: U256,
}

pub trait StealthGasStationHelper<T, P>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T> + Send + Sync + 'static,
{
    fn init(address: Address, provider: P) -> Self;
    fn payload_send_gas_tickets(
        &self,
        blind_sigs: Vec<BlindedSignature>
    ) -> StealthGasPayload;
}

impl<T, P> StealthGasStationHelper<T, P> for IStealthGasStationInstance<T, P>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T> + Send + Sync + 'static,
{
    fn init(address: Address, provider: P) -> Self {
        IStealthGasStationInstance::new(address, provider)
    }

    fn payload_send_gas_tickets(
        &self,
        blind_sigs: Vec<BlindedSignature>,
    ) -> StealthGasPayload {
        let (ids, signatures): (Vec<FixedBytes<32>>, Vec<Bytes>) =
            blind_sigs.into_iter().map(|sig| (sig.id, sig.signature)).unzip();

        StealthGasPayload {
            target: self.address().to_owned(),
            data: self
                .sendGasTickets(ids.into(), signatures.into())
                .calldata()
                .to_owned(),
            value: U256::ZERO,
        }
    }
}
