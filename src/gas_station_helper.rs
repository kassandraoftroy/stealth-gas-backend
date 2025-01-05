use alloy::{
    primitives::{Bytes, FixedBytes, U256, Address},
    providers::Provider,
    sol,
    transports::Transport,
};
use serde::Serialize;
use eth_stealth_gas_tickets::BlindedSignature;

sol! {
    #[derive(Debug, Serialize)]
    #[sol(rpc)]
    interface IStealthGasStation {
        function sendGasTickets(bytes32[] calldata ids, bytes[] calldata signed) external;
        function sendGas(uint256[] calldata amounts, address[] calldata targets, bytes calldata metadata) external;
    }
}

pub use IStealthGasStation::IStealthGasStationInstance;

pub struct StealthGasPayload {
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
    fn payload_send_gas(
        &self,
        amounts: Vec<U256>,
        targets: Vec<Address>
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
            blind_sigs.into_iter().map(|sig| (sig.id, sig.blind_sig)).unzip();

        StealthGasPayload {
            data: self
                .sendGasTickets(ids.into(), signatures.into())
                .calldata()
                .to_owned(),
            value: U256::ZERO,
        }
    }

    fn payload_send_gas(
        &self,
        amounts: Vec<U256>,
        targets: Vec<Address>
    ) -> StealthGasPayload {
        StealthGasPayload {
            data: self.sendGas(amounts.clone(), targets, Bytes::default()).calldata().to_owned(),
            value: amounts.into_iter().sum(),
        }
    }
}
