use ethers::{
    contract::Contract,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::{Bytes, TransactionReceipt, U256, H160, H256},
    middleware::{SignerMiddleware, Middleware},
    prelude::{abigen, k256},
};
use std::{sync::Arc, convert::TryFrom};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use log::{debug, info};
use dotenv::dotenv;
use std::env;
use crate::power::PowerReadings;
use crate::sensors::SensorReadings;
use crate::gps::Location;
use sha2::{Sha256, Digest};
use hex;

// Generate types from EnergyDataBridge ABI
abigen!(
    EnergyDataBridge,
    "./src/contracts/EnergyDataBridge.json",
    event_derives(serde::Serialize, serde::Deserialize)
);

// Print contract types during compilation
#[allow(dead_code)]
fn print_contract_types() {
    println!("Contract types generated:");
    
    // We'll add comments here with the expected types
    // The abigen macro should generate:
    // - EnergyDataBridge: main contract struct
    // - EnergyData: struct for energy data
    // - P2PConsensusProof: struct for consensus proof
}

// Define our own data structures for blockchain interaction
#[derive(Debug, Clone)]
pub struct EnergyData {
    pub timestamp: u64,
    pub energy_kwh: f64,
    pub location: Location,
    pub device_id: String,
    pub temperature: f32,
    pub humidity: f32,
    pub solar_radiation: f32,
    pub carbon_offset: f64,
}

#[derive(Debug, Clone)]
pub struct P2PConsensusProof {
    pub device_id: String,
    pub verifier_node_ids: Vec<String>,
    pub verification_timestamp: u64,
    pub verification_hash: String,
    pub signature_count: u32,
}

#[derive(Debug)]
pub struct BlockchainClient {
    provider: Arc<Provider<Http>>,
    wallet: Wallet<k256::ecdsa::SigningKey>,
    energy_bridge: EnergyDataBridge<SignerMiddleware<Arc<Provider<Http>>, Wallet<k256::ecdsa::SigningKey>>>,
    chain_id: U256,
}

impl BlockchainClient {
    pub async fn new() -> Result<Self> {
        dotenv().ok();
        
        // Load environment variables
        let rpc_url = env::var("BLOCKCHAIN_RPC_URL")
            .map_err(|_| anyhow!("BLOCKCHAIN_RPC_URL environment variable not set"))?;
        
        let private_key = env::var("BLOCKCHAIN_PRIVATE_KEY")
            .map_err(|_| anyhow!("BLOCKCHAIN_PRIVATE_KEY environment variable not set"))?;
        
        let contract_address = env::var("ENERGY_BRIDGE_ADDRESS")
            .map_err(|_| anyhow!("ENERGY_BRIDGE_ADDRESS environment variable not set"))?;

        // Create provider and wallet
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let provider_arc = Arc::new(provider);
        
        let chain_id = provider_arc.get_chainid().await?;
        
        let wallet = private_key
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id.as_u64());

        // Create middleware
        let client = SignerMiddleware::new(provider_arc.clone(), wallet.clone());
        let client = Arc::new(client);
        
        // Create contract instance
        let contract_address = contract_address.parse::<H160>()?;
        let energy_bridge = EnergyDataBridge::new(contract_address, client);
        
        Ok(Self {
            provider: provider_arc,
            wallet,
            energy_bridge,
            chain_id,
        })
    }
    
    // Convert a single data point to contract format
    fn convert_to_contract_data(&self, device_id: &str, power_readings: &PowerReadings, 
                               sensor_readings: &SensorReadings, location: &Location) -> Result<(String, [u8; 32])> {
        // Create energy data hash
        let mut hasher = Sha256::new();
        
        // Calculate energy in kWh
        let energy_kwh = U256::from((power_readings.power_produced_kwh * 1000.0) as u64);
        
        // Convert GPS coordinates to contract format (6 decimal precision integers)
        let latitude_int = (location.latitude * 1_000_000.0) as i32;
        let longitude_int = (location.longitude * 1_000_000.0) as i32;
        
        // Use average of temperature1 and temperature2 from sensor readings
        let temperature_int = ((sensor_readings.temperature1 + sensor_readings.temperature2) / 2.0 * 100.0) as i32;
        
        // Use light intensity as a proxy for humidity since we don't have a direct humidity sensor
        let humidity_int = match sensor_readings.ldr_intensity.as_str() {
            "Dark" => 85,      // Dark often means higher humidity
            "Dim" => 75,
            "Normal" => 65,
            "Bright" => 55,
            "Very Bright" => 45, // Bright often means lower humidity
            _ => 50,           // Default
        };
        
        // Use LDR value (normalized to 0-100%) as a proxy for solar radiation
        let max_ldr = 1024; // Assumed max value based on the code
        let solar_radiation_int = ((sensor_readings.ldr_value as f64 / max_ldr as f64) * 100.0) as i32;
        
        // Calculate carbon offset (1kWh = ~0.5kg CO2 avoided with solar)
        let carbon_offset = U256::from((power_readings.power_produced_kwh * 500.0) as u64); // in grams
        
        // Create a composite string of all values to hash
        let timestamp = U256::from(location.timestamp);
        let data_string = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            timestamp, energy_kwh, latitude_int, longitude_int, 
            temperature_int, humidity_int, solar_radiation_int, carbon_offset
        );
        
        // Hash the data
        hasher.update(data_string.as_bytes());
        let result = hasher.finalize();
        
        // Create consensus proof hash (device_id + data_hash)
        let mut consensus_hasher = Sha256::new();
        consensus_hasher.update(device_id.as_bytes());
        consensus_hasher.update(&result);
        let consensus_hash = consensus_hasher.finalize();
        
        let data_hash_hex = hex::encode(result);
        let consensus_hash_array: [u8; 32] = consensus_hash.as_slice().try_into()?;
        
        Ok((data_hash_hex, consensus_hash_array))
    }
    
    // Submit a batch of energy data to the blockchain
    pub async fn submit_energy_data_batch(
        &self, 
        device_id: &str,
        _power_readings: &PowerReadings,
        _sensor_readings: &SensorReadings,
        _location: &Location
    ) -> Result<H256> {
        info!("MOCK: Submitting energy data batch for device: {}", device_id);

        // This is a mock implementation
        // In a real implementation, we would use the actual contract function
        // Return a mock transaction hash for now
        let mock_tx_hash = H256::from([1u8; 32]);
        info!("MOCK: Energy data batch submitted. Transaction hash: {}", mock_tx_hash);
        
        Ok(mock_tx_hash)
    }
    
    // Process a batch after verification period
    pub async fn process_batch(&self, batch_hash: H256) -> Result<TransactionReceipt> {
        info!("MOCK: Processing batch: {}", batch_hash);
        
        // Create a mock transaction receipt
        let tx_hash = H256::from([2u8; 32]);
        
        // Since TransactionReceipt is maintained by the ethers-rs library
        // and may change between versions, we'll use a simpler approach
        // to create a mock receipt
        
        // For testing/mocking purposes, simply return a transaction hash instead
        info!("MOCK: Batch processed. Transaction hash: {}", tx_hash);
        
        Err(anyhow!("Mocked implementation - in production this would return a TransactionReceipt"))
    }
    
    // Check if a batch is ready for processing
    pub async fn is_batch_processable(&self, batch_hash: H256) -> Result<bool> {
        info!("MOCK: Checking if batch is processable: {}", batch_hash);
        
        // In a production environment, this would check the actual batch status
        // For testing, simply return true
        Ok(true)
    }
    
    // Listen for events
    pub async fn listen_for_events(&self) -> Result<()> {
        // This would normally be implemented with WebSocket provider
        // HTTP provider doesn't support subscriptions
        info!("Event listening not supported with HTTP provider");
        Ok(())
    }
} 