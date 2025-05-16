use ethers::{
    providers::{Http, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::{TransactionReceipt, U256, H160, H256},
    middleware::{SignerMiddleware, Middleware},
    prelude::{abigen, k256},
};
use std::{sync::Arc, convert::TryFrom, error::Error};
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
use libp2p::identity::{PublicKey, ed25519};
use std::str::FromStr;

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
    #[allow(dead_code)]
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
        info!("Submitting energy data batch for device: {}", device_id);

        // Mock implementation - this will be replaced with actual implementation when ready
        info!("Mock implementation for energy data batch submission until contract structure finalized");
        let mock_tx_hash = H256::from([1u8; 32]);
        Ok(mock_tx_hash)
    }
    
    // Process a batch after verification period
    pub async fn process_batch(&self, batch_hash: H256) -> Result<TransactionReceipt> {
        info!("Processing batch: {}", batch_hash);
        
        // Convert H256 to [u8; 32] using into()
        let batch_hash_bytes: [u8; 32] = batch_hash.into();
        
        // Call the processBatch function
        let contract_call = self.energy_bridge.process_batch(batch_hash_bytes);
        let tx = contract_call.send().await?;
        let receipt = tx.await?;
        
        if let Some(receipt_value) = receipt {
            info!("Batch processed. Transaction hash: {}", receipt_value.transaction_hash);
            Ok(receipt_value)
        } else {
            Err(anyhow!("Failed to get transaction receipt"))
        }
    }
    
    // Check if a batch is ready for processing
    pub async fn is_batch_processable(&self, batch_hash: H256) -> Result<bool> {
        info!("Checking if batch is processable: {}", batch_hash);
        
        // Convert H256 to [u8; 32] using into()
        let batch_hash_bytes: [u8; 32] = batch_hash.into();
        
        // Get batch submission time
        let submission_time = self.energy_bridge
            .batch_submission_times(batch_hash_bytes)
            .call()
            .await?;
        
        // Get the processing delay
        let delay = self.energy_bridge
            .batch_processing_delay()
            .call()
            .await?;
        
        // Get current block time
        let current_block = self.provider.get_block_number().await?;
        let block = self.provider.get_block(current_block).await?;
        let current_time = block
            .ok_or_else(|| anyhow!("Failed to get block"))?
            .timestamp
            .as_u64();
        
        // Check if enough time has passed
        let processable = submission_time.as_u64() + delay.as_u64() <= current_time;
        
        info!("Batch {} is {}", batch_hash, 
              if processable { "ready for processing" } else { "not ready for processing yet" });
        
        Ok(processable)
    }
    
    // Get wallet address as string (public method to access private field)
    pub fn get_wallet_address(&self) -> String {
        self.wallet.address().to_string()
    }
    
    // Register a node with the smart contract
    pub async fn register_node(&self, peer_id_str_for_log: &str, peer_id_bytes: [u8; 32]) -> Result<H256> {
        info!("Registering node (original PeerID: {}) with Peer ID as bytes32: 0x{}", 
              peer_id_str_for_log, hex::encode(peer_id_bytes));
        
        // Get the wallet address (the operator of the node)
        let operator_address = self.wallet.address();
        
        // Call the registerNode function on the contract
        let contract_call = self.energy_bridge.register_node(peer_id_bytes, operator_address);
        let tx = contract_call.send().await?;
        let receipt = tx.await?;
        
        // Get the transaction hash
        if let Some(receipt_value) = receipt {
            let tx_hash = receipt_value.transaction_hash;
            info!("Node registered successfully. Transaction hash: {}", tx_hash);
            Ok(tx_hash)
        } else {
            Err(anyhow!("Failed to get transaction receipt for node registration"))
        }
    }
    
    // Grant a role to an address
    pub async fn grant_role(&self, role_name: &str, account: &str) -> Result<H256> {
        info!("Granting role {} to account {}", role_name, account);
        
        // Convert role name to bytes32 role identifier
        let role = match role_name {
            "DATA_SUBMITTER_ROLE" => self.energy_bridge.data_submitter_role().call().await?,
            "NODE_MANAGER_ROLE" => self.energy_bridge.node_manager_role().call().await?,
            "PAUSER_ROLE" => self.energy_bridge.pauser_role().call().await?,
            "UPGRADER_ROLE" => self.energy_bridge.upgrader_role().call().await?,
            "DEFAULT_ADMIN_ROLE" => self.energy_bridge.default_admin_role().call().await?,
            _ => return Err(anyhow!("Unknown role: {}", role_name)),
        };
        
        // Parse account address
        let account_address = account.parse::<H160>()?;
        
        // Call the grantRole function - fix temporary value issue
        let contract_call = self.energy_bridge.grant_role(role, account_address);
        let tx = contract_call.send().await?;
        let receipt = tx.await?;
        
        // Get the transaction hash
        if let Some(receipt_value) = receipt {
            let tx_hash = receipt_value.transaction_hash;
            info!("Role {} granted to account {} successfully. Transaction hash: {}", 
                  role_name, account, tx_hash);
            Ok(tx_hash)
        } else {
            Err(anyhow!("Failed to get transaction receipt for role granting"))
        }
    }
    
    // Grant the DATA_SUBMITTER_ROLE to a node operator
    pub async fn grant_submitter_role(&self, account: &str) -> Result<H256> {
        self.grant_role("DATA_SUBMITTER_ROLE", account).await
    }
}

// New function to convert Peer ID string to raw Ed25519 public key bytes
pub fn get_raw_ed25519_pubkey_from_peer_id_str(peer_id_str: &str) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
    use libp2p::identity::PeerId;
    use std::str::FromStr;

    // Parse the PeerId from the string
    let peer_id = PeerId::from_str(peer_id_str)
        .map_err(|e| format!("Failed to parse Peer ID string '{}': {}", peer_id_str, e))?;
    
    // Get the bytes representation of the PeerId (which is a multihash)
    let multihash_bytes = peer_id.to_bytes();
    
    // For Ed25519 keys with identity hash, we expect a specific pattern:
    // - The first few bytes are the multihash header (usually 0x00 for identity hash, plus length)
    // - The remaining bytes should contain a protobuf-encoded PublicKey
    // - For Ed25519, this should be a 32-byte key

    // Check if the multihash is an identity hash (code 0)
    // A basic check would be to look for a pattern indicating an Ed25519 key
    if multihash_bytes.len() >= 35 {  // Minimum reasonable length
        // Skip the multihash header and try to extract the key
        // For Ed25519 keys, we typically expect the last 32 bytes to be the actual key
        let key_bytes = &multihash_bytes[multihash_bytes.len() - 32..];
        
        let mut result = [0u8; 32];
        result.copy_from_slice(key_bytes);
        
        Ok(result)
    } else {
        Err(format!("Peer ID '{}' does not appear to be an identity-hashed Ed25519 key", peer_id_str).into())
    }
} 