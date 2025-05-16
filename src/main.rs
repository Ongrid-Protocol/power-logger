use std::{error::Error, hash::{Hash, Hasher},collections::hash_map::DefaultHasher,
 collections::{HashSet, HashMap, VecDeque}, fs::{File, OpenOptions}, path::Path, 
 io::{self, Write}, env, sync::{Arc, Mutex}, 
 time::{SystemTime, UNIX_EPOCH}, net::{UdpSocket}, process::Command};
use serde::{Deserialize, Serialize};
use futures::prelude::*;
use libp2p::{identity, noise, ping, gossipsub, mdns, swarm::{SwarmEvent, NetworkBehaviour}, tcp, yamux, Multiaddr, PeerId, multiaddr::Protocol};
use tracing_subscriber::EnvFilter;
use ic_agent::{Agent};
use candid::{CandidType, Principal, Deserialize as CandidDeserialize};
use tokio::time::{interval, Duration};
use sha2::{Sha256, Digest};
use hex;
use serde_json;
use chrono::Utc; // Add chrono for timestamps
use std::time::Instant; // Import Instant for duration checking if needed later
use std::fs;
use power_logger::gps::{Location, Country};
use power_logger::config::{Config};
use power_logger::sensors::SensorReadings;
use power_logger::power::PowerReadings;
use power_logger::messaging::{RabbitMQClient, VerifiedData};
use power_logger::blockchain::BlockchainClient;
use power_logger::devices_yaml;
use anyhow::Result;

// Define the minimum number of nodes required for verification
const MIN_NODES_FOR_VERIFICATION: usize = 3;

// Define the structure for signed messages
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SignedMessage {
    content: String,
    originator_id: String,
    message_hash: String,
    signatures: HashSet<String>,
    sensor_readings: SensorReadings,
    power_readings: PowerReadings,
    location: Location,
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalConfig {
    node: NodeSettings,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeSettings {
    port: u16,
    ic: ICSettings,
    peer_nodes: Vec<String>,
    rabbitmq: power_logger::config::RabbitMQSettings,
    sensors: power_logger::config::SensorSettings,
}

#[derive(Debug, Serialize, Deserialize)]
struct ICSettings {
    network: String,
    canister_id: String,
    is_local: bool,
    url: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
struct Node {
    node_principal: Principal,
    multiaddress: String,
    last_heartbeat: u64,
}

#[derive(CandidType, CandidDeserialize, Debug)]
struct RegisterResponse {
    success: bool,
    node_principal: Principal,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

type MessageStore = Arc<Mutex<HashMap<String, SignedMessage>>>;
type VerificationCounter = Arc<Mutex<u64>>;
type FailedPublishQueue = Arc<Mutex<VecDeque<SignedMessage>>>; // Use VecDeque for FIFO retry

// Log file structure
type LogFile = Arc<Mutex<File>>; // Corrected: Direct File access

// Add network metrics structure
#[derive(Debug, Default)]
struct NetworkMetrics {
    connection_attempts: u64,
    successful_connections: u64,
    failed_connections: u64,
    connection_durations: Vec<Duration>,
    message_latencies: Vec<Duration>,
    mesh_peer_counts: Vec<usize>,
    last_heartbeat_time: Option<Instant>,
}

// Add RetryPeer structure to store information about peers to retry
#[derive(Debug, Clone)]
struct RetryPeer {
    peer_id: PeerId,
    multiaddr: Multiaddr,
    retry_count: usize,
    last_attempt: SystemTime,
}

#[derive(Serialize, Deserialize, Debug)]
struct PowerData {
    timestamp: u64,
    sensor_readings: SensorReadings,
    power_readings: PowerReadings,
    device_id: String,
    location: Location,
}

type RetryList = Arc<Mutex<Vec<RetryPeer>>>;

async fn write_log(log_file: &LogFile, message: String) {
    let mut file_guard = log_file.lock().unwrap();
    let timestamped_message = format!("[{}] {}\n", Utc::now().to_rfc3339(), message);
    if let Err(e) = file_guard.write_all(timestamped_message.as_bytes()) {
        eprintln!("Failed to write to verification log: {}", e); // Log errors to stderr
    }
    // To ensure data is written promptly, especially if the program might panic,
    // an explicit flush might be considered, though write_all to a File often flushes.
    // However, frequent explicit flushes can impact performance.
    // if let Err(e) = file_guard.flush() {
    //     eprintln!("Failed to flush verification log: {}", e);
    // }
}

async fn register_node(agent: &Agent, canister_id: &Principal, node_principal: Principal, multiaddr: &str, otp: &str, peer_id: &str) -> Result<RegisterResponse, Box<dyn Error + Send + Sync>> {
    let response = agent
        .update(canister_id, "register_node")
        .with_arg(candid::encode_args((
            multiaddr,
            node_principal,
            otp,
            peer_id,
        ))?)
        .call_and_wait()
        .await?;

    let result: RegisterResponse = candid::decode_one(&response)?;
    Ok(result)
}

async fn send_heartbeat(agent: &Agent, canister_id: &Principal, node_principal: Principal, multiaddr: &str) -> Result<bool, Box<dyn Error>> {
    let response = agent
        .update(canister_id, "heartbeat")
        .with_arg(candid::encode_args((
            node_principal,
            multiaddr,
        ))?)
        .call_and_wait()
        .await?;

    let result: bool = candid::decode_one(&response)?;
    Ok(result)
}

async fn fetch_peer_nodes(agent: &Agent, config: &NodeSettings) -> Result<Vec<String>, Box<dyn Error>> {
    let canister_id = Principal::from_text(&config.ic.canister_id)?;
    let response = agent
        .query(&canister_id, "get_nodes")
        .with_arg(candid::encode_args(()).unwrap())
        .call()
        .await?;

    let nodes: Vec<Node> = candid::decode_one(&response)?;
    
    Ok(nodes.into_iter()
        .map(|node| node.multiaddress)
        .collect())
}

fn open_file(path: &Path) -> Result<File, Box<dyn Error>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.is_dir() {
        return Err(format!("Expected a file but found a directory: {}", path.display()).into());
    }

    let file = std::fs::File::open(path)?;
    Ok(file)
}


fn load_config() -> Result<(LocalConfig, Config), Box<dyn Error>> {
    let config_path = Path::new("config.yaml");
    let config_devices_path = Path::new("devices.yaml");
    
    // Load main config
    let file = open_file(config_path)?;
    let node_config: LocalConfig = serde_yaml::from_reader(file)?;
    
    // Load devices config
    let device_file = open_file(config_devices_path)?;
    let devices_config: Config = serde_yaml::from_reader(device_file)?;

    Ok((node_config, devices_config))
}



fn save_principal_id(principal: &Principal) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("node_principal.txt")?;
    
    file.write_all(principal.to_string().as_bytes())?;
    Ok(())
}


async fn get_public_ip() -> Result<String, Box<dyn Error>> {
    // Try to get public IP from environment first
    if let Ok(ip) = env::var("PUBLIC_IP") {
        return Ok(ip);
    }

    // Try to get public IP by connecting to a public service
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?; // Google's DNS
    let local_addr = socket.local_addr()?;
    let ip = local_addr.ip().to_string();
    
    println!("Detected public IP: {}", ip);
    Ok(ip)
}

fn save_private_key(keypair: &identity::Keypair) -> Result<(), Box<dyn Error>> {
    let bytes = keypair.to_protobuf_encoding()?;
    fs::write("node_private_key.bin", bytes)?;
    Ok(())
}

fn load_private_key() -> Result<Option<identity::Keypair>, Box<dyn Error>> {
    if !Path::new("node_private_key.bin").exists() {
        return Ok(None);
    }
    let bytes = fs::read("node_private_key.bin")?;
    Ok(Some(identity::Keypair::from_protobuf_encoding(&bytes)?))
}

// Function to test network connectivity to a given host
fn test_connectivity(target_ip: &str) -> bool {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(&["-n", "1", "-w", "1000", target_ip])
        .output();

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("ping")
        .args(&["-c", "1", "-W", "1", target_ip])
        .output();

    match output {
        Ok(output) => {
            let success = output.status.success();
            println!("Ping test to {}: {}", target_ip, if success { "SUCCESS" } else { "FAILED" });
            success
        }
        Err(e) => {
            println!("Failed to execute ping command: {}", e);
            false
        }
    }
}

impl PowerData {
    fn new_plain(peer_id: &str, current_devices_config: &Config) -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
    
        // Get device configuration
        let device_config = current_devices_config.get_device_by_peer_id(peer_id)
            .ok_or_else(|| format!("Device with peer_id {} not found in configuration", peer_id))?;
        
        // Get location from device configuration
        let location = current_devices_config.get_device_location(peer_id)
            .map(|loc| loc.clone())
            .unwrap_or_else(|| {
                println!("Warning: Using default location for device {}", peer_id);
                Location {
                    latitude: 37.7749,
                    longitude: -122.4194,
                    timestamp,
                    accuracy: 5.0,
                    satellites: 8,
                    altitude: 0.0,
                    country: Some(Country {
                        code: "US".to_string(),
                        name: "United States".to_string(),
                        region: "North America".to_string(),
                    }),
                }
            });
        
        // Load LocalConfig settings for RabbitMQ and Sensors
        let local_config_settings: LocalConfig = File::open("config.yaml")
            .map_err(|e| format!("Failed to open config.yaml: {}", e))
            .and_then(|file| {
                serde_yaml::from_reader(file)
                    .map_err(|e| format!("Failed to parse config.yaml: {}", e))
            })?;
        
        let node_config = power_logger::config::NodeConfig {
            rabbitmq: local_config_settings.node.rabbitmq.clone(),
            sensors: local_config_settings.node.sensors.clone(),
        };
        
        // Create sensor and power readings
        let sensor_readings = SensorReadings::new(&node_config);
        let power_readings = PowerReadings::new_with_sensors(device_config, &sensor_readings);
    
        Ok(Self {
            timestamp,
            sensor_readings,
            power_readings,
            device_id: peer_id.to_string(),
            location,
        })
    }
}

// Helper function to reload devices.yaml into the Arc<Mutex<Config>>
async fn reload_devices_config_in_memory(config_devices_mutex: &Arc<Mutex<Config>>) {
    match File::open("devices.yaml") {
        Ok(file) => {
            match serde_yaml::from_reader::<_, Config>(file) {
                Ok(new_devices_config) => {
                    let mut guard = config_devices_mutex.lock().unwrap();
                    *guard = new_devices_config;
                    println!("In-memory devices_config reloaded successfully.");
                }
                Err(e) => {
                    eprintln!("Failed to parse updated devices.yaml for reloading: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open updated devices.yaml for reloading: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Load initial configurations
    let (local_node_initial_config, initial_devices_config_val) = load_config().expect("Failed to load initial main config");
    let config_devices: Arc<Mutex<Config>> = Arc::new(Mutex::new(initial_devices_config_val));
    // 'config' variable will now refer to local_node_initial_config for node-specific settings like port, IC URL etc.
    // The 'devices.yaml' content is managed by 'config_devices' Arc<Mutex<Config>>.

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // --- Log File Setup ---
    let log_path = format!("verification_log.txt");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_file: LogFile = Arc::new(Mutex::new(file));
    // --- End Log File Setup ---

    // Load or generate Keypair
    let id_keys = match load_private_key()? {
        Some(keys) => keys,
        None => {
            let id_keys = identity::Keypair::generate_ed25519();
            id_keys
        }
    };
    let peer_id = PeerId::from(id_keys.public());
    let peer_id_str = peer_id.to_string();

    println!("Peer ID: {}", peer_id);
    let public_key_bytes = id_keys.public().to_peer_id().to_base58();    
    let node_principal = Principal::self_authenticating(&public_key_bytes);
    let message_store: MessageStore = Arc::new(Mutex::new(HashMap::new()));
    let verification_counter: VerificationCounter = Arc::new(Mutex::new(0));
    let failed_publish_queue: FailedPublishQueue = Arc::new(Mutex::new(VecDeque::new()));
    let retry_list: RetryList = Arc::new(Mutex::new(Vec::new()));

    let ic_url = env::var("IC_URL").unwrap_or_else(|_| {
        println!("Warning: IC_URL environment variable not set, using URL from config.yaml");
        local_node_initial_config.node.ic.url.clone()
    });
    println!("Using IC URL: {}", ic_url);

    let agent = Agent::builder()
        .with_url(&ic_url)
        .build()?;

    if local_node_initial_config.node.ic.is_local {
        // Replace agent.fetch_root_key() with setting the root key directly
        let root_key = [48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 136, 201, 253, 94, 79, 41, 135, 119, 75, 188, 202, 25, 226, 219, 55, 96, 203, 241, 179, 103, 141, 102, 242, 178, 5, 22, 148, 33, 191, 9, 17, 25, 216, 215, 88, 94, 53, 36, 21, 101, 186, 65, 244, 248, 54, 188, 28, 227, 0, 67, 163, 55, 74, 199, 152, 176, 232, 112, 180, 61, 143, 237, 178, 143, 112, 59, 34, 223, 222, 241, 129, 122, 203, 185, 96, 84, 4, 113, 251, 187, 72, 122, 14, 38, 28, 61, 12, 183, 144, 63, 25, 111, 4, 208, 239, 228];
        agent.set_root_key(root_key.to_vec());
    }

    let canister_id = Principal::from_text(&local_node_initial_config.node.ic.canister_id)?;
    // Get the public IP address
    let public_ip = get_public_ip().await?;
    let public_multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", public_ip, local_node_initial_config.node.port, peer_id);

    // Check if this is a new node (no private key file existed)
    if !Path::new("node_private_key.bin").exists() {
        println!("This appears to be a new node registration.");
        let mut registration_success = false;
        
        while !registration_success {
            println!("Please enter the OTP provided by the canister (or 'exit' to quit):");
            let mut otp = String::new();
            std::io::stdin().read_line(&mut otp)?;
            let otp = otp.trim().to_string();
            
            if otp.to_lowercase() == "exit" {
                println!("Exiting node registration...");
                return Ok(());
            }
            
            println!("Registering with OTP: {}", otp);
            
            match register_node(
                &agent,
                &canister_id,
                node_principal,
                &public_multiaddr,
                &otp,
                &peer_id_str
            ).await {
                Ok(response) => {
                    if response.success {
                        println!("Successfully registered node with canister using OTP");
                        if let Err(e) = save_principal_id(&response.node_principal) {
                            println!("Failed to save principal ID: {}", e);
                        }
                        save_private_key(&id_keys)?;

                        // After successful OTP registration, fetch/update devices.yaml
                        if let Err(e) = devices_yaml::fetch_and_save_devices_yaml(&agent, &canister_id).await {
                            println!("Error updating devices.yaml from canister: {}", e);
                            println!("WARNING: Proceeding with potentially stale or missing device information for blockchain registration.");
                        } else {
                            reload_devices_config_in_memory(&config_devices).await;
                            println!("devices.yaml fetched from canister and reloaded into memory.");
                        }

                        // Retrieve operator wallet address for the current node from the updated devices.yaml
                        let operator_wallet_address = {
                            let locked_devices_config = config_devices.lock().unwrap();
                            locked_devices_config.get_device_by_peer_id(&peer_id_str)
                                .map(|device| device.wallet_address.clone())
                                .unwrap_or_else(|| {
                                    println!("WARNING: Could not find Peer ID {} in the updated devices.yaml to retrieve its operator wallet address.", peer_id_str);
                                    println!("Blockchain registration might require manual wallet input later or may fail if the address is needed by the contract.");
                                    "WALLET_ADDRESS_NOT_FOUND_IN_DEVICES_YAML".to_string()
                                })
                        };

                        println!("\n--- Node Details for Blockchain Registration ---");
                        println!("Current Node Peer ID: {}", peer_id_str);
                        println!("Retrieved Operator Wallet Address (from devices.yaml): {}", operator_wallet_address);
                        println!("----------------------------------------------\n");

                        println!("The next step is to register this node (Peer ID: {}) with the blockchain.", peer_id_str);
                        println!("This typically uses the operator wallet address ({}) associated with it in the devices.yaml file provided by the canister.", operator_wallet_address);
                        println!("Do you want to proceed with registering this node on the blockchain? (yes/no):");
                        
                        let mut proceed_with_blockchain_reg_input = String::new();
                        std::io::stdin().read_line(&mut proceed_with_blockchain_reg_input)?;
                        
                        if proceed_with_blockchain_reg_input.trim().to_lowercase() == "yes" {
                            match BlockchainClient::new().await {
                                Ok(blockchain_client) => {
                                    println!("Attempting to register node {} on the blockchain...", peer_id_str);
                                    match blockchain_client.register_node(&peer_id_str).await {
                                        Ok(tx_hash) => {
                                            println!("Blockchain node registration transaction submitted successfully.");
                                            println!("Transaction Hash: {}", tx_hash);
                                            
                                            let mut blockchain_confirmed_by_user = false;
                                            while !blockchain_confirmed_by_user {
                                                println!("\nPlease monitor the transaction (Hash: {}) on a blockchain explorer.", tx_hash);
                                                println!("Has the node registration (Peer ID: {}) been confirmed on the blockchain? (yes/no/skip):", peer_id_str);
                                                let mut confirmation_input = String::new();
                                                std::io::stdin().read_line(&mut confirmation_input)?;
                                                match confirmation_input.trim().to_lowercase().as_str() {
                                                    "yes" => {
                                                        println!("Blockchain registration confirmed by user for Peer ID {}.", peer_id_str);
                                                        blockchain_confirmed_by_user = true;
                                                        registration_success = true; // Overall new node setup process successful
                                                    }
                                                    "no" => {
                                                        println!("Please continue to monitor the transaction. Confirm once it's processed on the blockchain.");
                                                    }
                                                    "skip" => {
                                                        println!("Skipping blockchain registration confirmation by user request for Peer ID {}.", peer_id_str);
                                                        println!("Node setup will proceed. Ensure the node is registered on the blockchain manually if issues arise with blockchain-related features.");
                                                        blockchain_confirmed_by_user = true;
                                                        registration_success = true; // Overall new node setup successful (with skipped confirmation)
                                                    }
                                                    _ => {
                                                        println!("Invalid input. Please enter 'yes', 'no', or 'skip'.");
                                                    }
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            println!("Error during blockchain node registration for Peer ID {}: {}", peer_id_str, e);
                                            println!("Node registration on the blockchain failed. You may need to retry or register manually via other means.");
                                            // registration_success remains false, OTP loop will continue or user can exit.
                                        }
                                    }
                                    // Granting submitter role is removed as per user request.
                                },
                                Err(e) => {
                                    println!("Failed to initialize Blockchain client: {}", e);
                                    println!("Skipping blockchain registration steps for Peer ID {}.", peer_id_str);
                                    println!("Node setup will proceed. The node is registered with the canister but NOT the blockchain. Blockchain-related features will be unavailable.");
                                    registration_success = true; // OTP part done, proceed without blockchain.
                                }
                            }
                        } else {
                            println!("Blockchain registration for Peer ID {} was cancelled by the user.", peer_id_str);
                            println!("Node setup will proceed. The node is registered with the canister but NOT the blockchain.");
                            registration_success = true; // OTP part done, user chose to skip blockchain for now.
                        }
                    } else { // OTP registration with canister failed
                        println!("Failed to register node with canister. Invalid OTP or other issue. Please try again.");
                        // registration_success remains false, OTP loop continues.
                    }
                }
                Err(e) => {
                    println!("Error during canister registration call: {}. Please try again.", e);
                    // registration_success remains false, OTP loop continues.
                }
            }
        }
    } else { // Node already has a private key, existing node flow
        println!("Node already registered, skipping OTP registration flow.");
        // Existing node - try to register with canister (heartbeat/re-affirm) without OTP
        match register_node(
            &agent,
            &canister_id,
            node_principal,
            &public_multiaddr,
            "", // Empty OTP for existing nodes
            &peer_id_str
        ).await {
            Ok(response) => {
                if response.success {
                    println!("Successfully registered node with canister");
                    println!("Assigned Principal ID: {}", response.node_principal);
                    if let Err(e) = save_principal_id(&response.node_principal) {
                        println!("Failed to save principal ID: {}", e);
                    }

                    // When a node reconnects:
                    if response.success {
                        // Fetch updated devices.yaml from canister and save it
                        if devices_yaml::fetch_and_save_devices_yaml(&agent, &canister_id).await.is_err() {
                            println!("Error updating devices.yaml on reconnect");
                        } else {
                            reload_devices_config_in_memory(&config_devices).await;
                        }
                    }
                } else {
                    println!("Failed to register node with canister");
                }
            }
            Err(e) => println!("Error registering node: {}", e),
        }
    }

    let fetched_nodes = fetch_peer_nodes(&agent, &local_node_initial_config.node).await?;

    let active_nodes: Vec<String> = fetched_nodes
        .into_iter()
        .filter(|addr_str| {
            if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                if let Some(Protocol::P2p(fetched_peer_id)) = ma.iter().last() {
                    if fetched_peer_id != peer_id { 
                        return true;
                    }
                }
            }
            false
        })
        .collect();

    println!("Filtered Peer Nodes (excluding self): {:?}", active_nodes);

    // Test connectivity to each unique IP in the active_nodes list
    println!("\n--- Testing network connectivity to peer IPs ---");
    let mut tested_ips = HashSet::new();
    for addr in &active_nodes {
        if let Ok(ma) = addr.parse::<Multiaddr>() {
            for protocol in ma.iter() {
                if let libp2p::multiaddr::Protocol::Ip4(ip) = protocol {
                    let ip_str = ip.to_string();
                    if !tested_ips.contains(&ip_str) {
                        tested_ips.insert(ip_str.clone());
                        test_connectivity(&ip_str);
                    }
                }
            }
        }
    }
    println!("--- End of network connectivity tests ---\n");

    let dialable_node_addrs: Vec<String> = active_nodes.iter().map(|addr_str| { 
        if let Ok(ma) = addr_str.parse::<Multiaddr>() {
            let components: Vec<_> = ma.iter().collect();
            if let Some(Protocol::Ip4(ip)) = components.get(0) {
                if !ip.is_loopback() && !ip.is_private() {
                    // Keep the original address
                    return addr_str.clone();
                }
            }
        }
        addr_str.clone()
    }).collect();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(30)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
                // signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;
            let ping = ping::Behaviour::new(ping::Config::new());


            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(MyBehaviour { gossipsub, mdns ,ping})


        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    let topic = gossipsub::IdentTopic::new("testing");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    println!("Subscribed to topic: {}", topic.hash());

    // Create listen address using public IP
    let listen_addr = format!("/ip4/{}/tcp/{}", public_ip, local_node_initial_config.node.port).parse()?;
    // let listen_addr_udp = format!("/ip4/{}/udp/{}/quic-v1", public_ip, node_config.node.port).parse()?;
    swarm.listen_on(listen_addr)?;
    // swarm.listen_on(listen_addr_udp)?;

    let mut target_peers = HashSet::new(); 
    for addr in &dialable_node_addrs { 
        if let Ok(remote_addr) = addr.parse::<Multiaddr>() {
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = remote_addr.iter().last() {
                target_peers.insert(peer_id);
                println!("Attempting to dial: {} at {}", peer_id, remote_addr);
                match swarm.dial(remote_addr.clone()) {
                    Ok(_) => {
                        println!("Dial initiated to node: {}", addr);
                    }
                    Err(e) => {
                        println!("Failed to dial {}: {} - Error type: {:?}", addr, e, e);
                        
                        // Add to retry list
                        let retry_peer = RetryPeer {
                            peer_id,
                            multiaddr: remote_addr,
                            retry_count: 0,
                            last_attempt: SystemTime::now(),
                        };
                        
                        let mut retry_list = retry_list.lock().unwrap();
                        retry_list.push(retry_peer);
                        println!("Added peer {} to retry list for later attempts", peer_id);
                    }
                }
            } else {
                println!("Could not extract PeerId from Multiaddr: {}", addr);
            }
        } else {
            println!("Failed to parse Multiaddr: {}", addr);
        }
    }

    // Set up intervals for various periodic tasks
    // Heartbeat every 1 minute (60 seconds)
    let mut heartbeat_interval = interval(Duration::from_secs(60));
    
    // Message verification every 10 minutes (600 seconds)
    let mut signing_request_interval = interval(Duration::from_secs(60)); 
    
    // Retry publishing failed messages every 30 seconds
    let mut retry_publish_interval = interval(Duration::from_secs(60));
    
    // Network metrics logging every minute
    let mut metrics_interval = interval(Duration::from_secs(60));
    
    // Network connection check every 10 seconds
    let _network_check_interval = interval(Duration::from_secs(10));
    
    // Connection retry interval every 15 seconds
    let mut connection_retry_interval = interval(Duration::from_secs(15));
    
    // Pre-verification node connection interval (5 seconds before verification)
    let mut pre_verification_connection_interval = interval(Duration::from_secs(595));

    // Interval for periodically syncing devices.yaml from the canister (e.g., every 10 minutes)
    let mut devices_sync_interval = interval(Duration::from_secs(30));

    let network_metrics: Arc<Mutex<NetworkMetrics>> = Arc::new(Mutex::new(NetworkMetrics::default()));
    
    let metrics_clone = network_metrics.clone();

    println!("Node initialized. Waiting for peers and network events.");

    let message_store_clone = message_store.clone();
    let verification_counter_clone = verification_counter.clone();
    let failed_publish_queue_clone = failed_publish_queue.clone();
    let local_peer_id = peer_id;
    let _keypair_clone = id_keys; // Prefix with underscore
    let log_file_clone = log_file.clone(); // Clone Arc for the main loop
    let retry_list_clone = retry_list.clone(); // Clone the retry list

    // Clone Arcs and copyables for the periodic devices.yaml sync task
    let agent_for_sync = agent.clone(); 
    let canister_id_for_sync = canister_id; // Principal is Copy
    let config_devices_for_sync = config_devices.clone(); 

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("\nNode Information:");
                        println!("Listening on: {}", address);
                        println!("Public Multiaddr: {}", public_multiaddr);
                    },
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("Connection established with peer: {}", peer_id);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        let mut metrics = metrics_clone.lock().unwrap();
                        metrics.successful_connections += 1;
                        metrics.connection_attempts += 1;
                        metrics.connection_durations.push(Duration::from_secs(0));
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        println!("mDNS discovered peers - Full details: {:?}", list);
                        for (peer_id, multiaddr) in list {
                            println!("Discovered peer {} at {}", peer_id, multiaddr);
                            // Verify the multiaddr is reachable
                            if !multiaddr.to_string().contains("127.0.0.1") { // Filter out loopback
                                if let Err(e) = swarm.dial(multiaddr.clone()) {
                                    println!("Failed to dial peer {}: {}", peer_id, e);
                                }
                            }
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("mDNS discover peer has expired: {peer_id}");
                            // Keep remove_explicit_peer if you added them previously,
                            // but since we removed the adding part, this might also be unnecessary
                            // unless other parts of the code add explicit peers. Let's keep it for now.
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id: _id,
                        message,
                    })) => {
                        let log_file_inner_clone = log_file_clone.clone(); // Clone for this specific event
                        let local_peer_id_str = local_peer_id.to_string(); // Get local peer id as string

                        if let Ok(received_message) = serde_json::from_slice::<SignedMessage>(&message.data) {
                            println!("[Gossipsub] Received SignedMessage: Hash {} from Peer {}. Payload Signatures: {:?}", 
                                received_message.message_hash, propagation_source, received_message.signatures);

                            let mut store = message_store_clone.lock().unwrap();
                            let message_hash = received_message.message_hash.clone();
                            
                            // Log signatures already in store for this hash BEFORE update
                            if let Some(existing_msg) = store.get(&message_hash) {
                                println!("[Gossipsub] Signatures for hash {} BEFORE update: {:?}", message_hash, existing_msg.signatures);
                            }
                            let initial_sig_count_before_update = store.get(&message_hash).map_or(0, |m| m.signatures.len());

                            let entry = store.entry(message_hash.clone()).or_insert_with(|| {
                                println!("[Gossipsub] Adding new message entry for hash: {}", message_hash); // Keep for debugging if needed
                                received_message.clone()
                            });

                            let mut signatures_added_now = HashSet::new();
                            let sender_peer_id_str = propagation_source.to_string();

                            // Add signatures from the received message payload
                            // Iterate over a reference (&) to avoid moving signatures
                            for sig_peer_id in &received_message.signatures {
                                if entry.signatures.insert(sig_peer_id.clone()) {
                                    signatures_added_now.insert(sig_peer_id.clone()); // Clone here as we need ownership for the set
                                }
                            }

                            // Add the signature of the peer who propagated the message to us
                            let mut sender_added = false;
                            if entry.signatures.insert(sender_peer_id_str.clone()) {
                                signatures_added_now.insert(sender_peer_id_str.clone());
                                sender_added = true;
                            }

                            let current_sig_count = entry.signatures.len();
                            println!("[Gossipsub] Signatures for hash {} AFTER update: {:?}. Initial count: {}, Current count: {}", 
                                message_hash, entry.signatures, initial_sig_count_before_update, current_sig_count);

                            let signatures_added_str = signatures_added_now.iter().cloned().collect::<Vec<_>>().join(",");

                            // Log reception and signature processing
                            write_log(
                                &log_file_inner_clone,
                                format!(
                                    "MSG_RECV Node={} From={} Hash={} PayloadSigs={} AddedNow=[{}] SenderAdded={} TotalSigs={}",
                                    local_peer_id_str,
                                    sender_peer_id_str,
                                    message_hash,
                                    received_message.signatures.len(), // Now valid to access .len()
                                    signatures_added_str,
                                    sender_added,
                                    current_sig_count
                                )
                            ).await;


                            // Check for verification threshold
                            let mut needs_republish = !signatures_added_now.is_empty(); // Republish if any new sig was added

                            if current_sig_count >= MIN_NODES_FOR_VERIFICATION && initial_sig_count_before_update < MIN_NODES_FOR_VERIFICATION {
                                let mut counter = verification_counter_clone.lock().unwrap();
                                *counter += 1;
                                println!("*** MESSAGE VERIFIED ({} signatures): Hash {} (Total Verified: {}) ***", 
                                    current_sig_count, message_hash, *counter);

                                // Log verification
                                write_log(
                                    &log_file_inner_clone,
                                    format!(
                                        "MSG_VERIFIED Node={} Hash={} SigCount={} TotalVerifiedCount={}",
                                        local_peer_id_str,
                                        message_hash,
                                        current_sig_count,
                                        *counter
                                    )
                                ).await;

                                // Get device configuration
                                println!("Looking up device with peer ID: {}", entry.originator_id);
                                let locked_devices_config = config_devices.lock().unwrap();
                                let device_config = locked_devices_config.get_device_by_peer_id(&entry.originator_id)
                                    .expect("Device configuration not found for originator_id");

                                // Create verified data structure
                                let verified_data = VerifiedData {
                                    message_hash: message_hash.clone(),
                                    device_id: device_config.id.clone(),
                                    device_name: device_config.node_name.clone(),
                                    device_type: device_config.device_type.clone(),
                                    wallet_address: device_config.wallet_address.clone(),
                                    max_wattage: device_config.specifications.max_wattage,
                                    voltage_range: device_config.specifications.voltage_range.clone(),
                                    frequency_range: device_config.specifications.frequency_range.clone(),
                                    battery_capacity: device_config.specifications.battery_capacity.clone(),
                                    phase_type: device_config.specifications.phase_type.clone(),
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    sensor_readings: entry.sensor_readings.clone(),
                                    power_readings: entry.power_readings.clone(),
                                    location: entry.location.clone(),
                                    verified_by: entry.signatures.iter().cloned().collect(),
                                    verification_count: current_sig_count as i32,
                                };

                                // Submit verified data to blockchain
                                if let Err(e) = submit_to_blockchain(&verified_data, &entry.originator_id, &config_devices).await {
                                    eprintln!("Failed to submit data to blockchain: {}", e);
                                }

                                // // Get RabbitMQ client
                                // if let Ok(rabbitmq_client) = RabbitMQClient::get_client().await {
                                //     // Publish verified data
                                //     if let Err(e) = rabbitmq_client.publish_verified_data(
                                //         verified_data,
                                //         &local_node_initial_config.node.rabbitmq.exchange,
                                //         &local_node_initial_config.node.rabbitmq.routing_key,
                                //     ).await {
                                //         eprintln!("Failed to publish verified data to RabbitMQ: {}", e);
                                //     } else {
                                //         println!("Successfully published verified data to RabbitMQ");
                                //     }
                                // } else {
                                //     eprintln!("Failed to get RabbitMQ client");
                                // }

                                needs_republish = false; // Don't republish if just verified
                            } else if current_sig_count >= MIN_NODES_FOR_VERIFICATION { // Check against MIN_NODES_FOR_VERIFICATION
                                println!("[Gossipsub] Message {} already has {} (>= threshold) signatures. Not re-triggering verification.", message_hash, current_sig_count);
                                needs_republish = false; // Already verified, no need to republish
                            }

                            if needs_republish {
                               write_log(
                                   &log_file_inner_clone,
                                   format!("MSG_REPUBLISH Node={} Hash={} NewSigCount={}", local_peer_id_str, message_hash, current_sig_count)
                               ).await;

                                match serde_json::to_string(&*entry) {
                                    Ok(json_message) => {
                                        if let Err(e) = swarm
                                            .behaviour_mut().gossipsub
                                            .publish(topic.clone(), json_message.as_bytes())
                                        {
                                            eprintln!("Republish error: {e:?}. Queuing for retry.");
                                            failed_publish_queue_clone.lock().unwrap().push_back(entry.clone());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Error serializing message for republish: {}. Queuing for retry.", e);
                                        failed_publish_queue_clone.lock().unwrap().push_back(entry.clone());
                                    }
                                }
                            }

                            let mut metrics = metrics_clone.lock().unwrap();
                            metrics.message_latencies.push(Duration::from_secs(0)); // You can measure actual latency if needed
                        } else {
                            println!(
                                "Got plain text message: '{}' from peer: {}",
                                String::from_utf8_lossy(&message.data),
                                propagation_source
                            );
                        }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Ping(_event)) => { // Prefix with underscore
                        // println!("Ping event: {:?}", event);
                    },
                    SwarmEvent::Dialing { peer_id, connection_id } => {
                        // println!("Dialing peer: {:?} on connection: {:?}", peer_id.map(|p| p.to_string()), connection_id);
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        // println!("Connection closed with peer: {}. Cause: {:?}", peer_id, cause);
                    },
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        // println!("Failed to connect to peer: {:?} - Error: {}", peer_id, error)
                        // println!("Failed to connect to peer: {:?} - Error: {}", peer_id, error);
                        // Add to failed connections metrics
                        let mut metrics = metrics_clone.lock().unwrap();
                        metrics.failed_connections += 1;
                        metrics.connection_attempts += 1;
                        
                        // If we have a peer_id, add to the retry list
                        if let Some(peer_id) = peer_id {
                            // println!("Will attempt to redial peer {} during the next retry cycle", peer_id);
                            
                            // Add to retry list if we have the multiaddr
                            for addr in &dialable_node_addrs {
                                if addr.contains(&peer_id.to_string()) {
                                    if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
                                        let retry_peer = RetryPeer {
                                            peer_id,
                                            multiaddr,
                                            retry_count: 0,
                                            last_attempt: SystemTime::now(),
                                        };
                                        
                                        let mut retry_list = retry_list_clone.lock().unwrap();
                                        // Check if already in list
                                        if !retry_list.iter().any(|p| p.peer_id == peer_id) {
                                            // println!("Added peer {} to retry list", peer_id);
                                            retry_list.push(retry_peer);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        
                    },
                    _ => {}
                }
            }
            
            // Heartbeat every 1 minute
            _ = heartbeat_interval.tick() => {
                // println!("Sending heartbeat to canister...");
                // Refresh public IP on each heartbeat
                let current_ip = get_public_ip().await?;
                let current_multiaddr = format!("/ip4/{}/tcp/{}/p2p/{}", current_ip, local_node_initial_config.node.port, local_peer_id);
                match send_heartbeat(
                    &agent,
                    &canister_id,
                    node_principal,
                    &current_multiaddr,
                ).await {
                    Ok(success) => {
                        if success {
                            println!("Heartbeat sent successfully");
                        } else {
                            println!("Heartbeat failed, will retry in next interval");
                        }
                    }
                    Err(e) => println!("Error sending heartbeat: {}", e),
                }

                let mut metrics = metrics_clone.lock().unwrap();
                metrics.last_heartbeat_time = Some(Instant::now());
            }
            
            // Try to connect to other nodes just before verification (5 seconds before)
            _ = pre_verification_connection_interval.tick() => {
                // println!("Pre-verification node connection check...");
                // Fetch the latest peers from the canister
                match fetch_peer_nodes(&agent, &local_node_initial_config.node).await {
                    Ok(new_fetched_nodes) => {
                        // Filter out our own node
                        let new_active_nodes: Vec<String> = new_fetched_nodes
                            .into_iter()
                            .filter(|addr_str| {
                                if let Ok(ma) = addr_str.parse::<Multiaddr>() {
                                    if let Some(Protocol::P2p(fetched_peer_id)) = ma.iter().last() {
                                        if fetched_peer_id != peer_id { 
                                            return true;
                                        }
                                    }
                                }
                                false
                            })
                            .collect();
                        
                        println!("Pre-verification: Found {} active peers to connect to", new_active_nodes.len());
                        
                        // Try to connect to all peers
                        for addr in &new_active_nodes {
                            if let Ok(remote_addr) = addr.parse::<Multiaddr>() {
                                if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = remote_addr.iter().last() {
                                    // println!("Pre-verification: Attempting to dial: {} at {}", peer_id, remote_addr);
                                    if let Err(e) = swarm.dial(remote_addr.clone()) {
                                        println!("Pre-verification: Failed to dial {}: {}", addr, e);
                                    } else {
                                        println!("Pre-verification: Dial initiated to node: {}", addr);
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        println!("Failed to fetch peer nodes before verification: {}", e);
                    }
                }
            }
            
            // Message verification every 10 minutes
            _ = signing_request_interval.tick() => {
                // println!("Starting message verification cycle...");
                // Check if we have enough nodes for verification
                let should_verify = devices_yaml::should_start_verification(&agent, &canister_id, MIN_NODES_FOR_VERIFICATION).await;
                if !should_verify {
                    println!("Skipping message verification due to insufficient node count.");
                    continue;
                }

                println!("Current peer count for verification: {}", swarm.connected_peers().count());
                let log_file_inner_clone = log_file_clone.clone();

                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                // Create non-encrypted data for this device only
                let local_peer_id_str = local_peer_id.to_string();
                let plain_data = PowerData::new_plain(&local_peer_id_str, &*config_devices.lock().unwrap())
                    .map_err(|e| {
                        eprintln!("Error creating power data: {}", e);
                        e
                    })?;
                let json_string = serde_json::to_string_pretty(&plain_data).unwrap_or_else(|e| {
                    eprintln!("Error serializing data: {}", e);
                    String::new()
                });
        
                // Print the generated data
                println!("\n--- {} Data Reading for Verification ---", local_peer_id_str);
                println!("{}", json_string);
                println!("-------------------\n");
                
                let message_content = json_string;

                let mut hasher = Sha256::new();
                hasher.update(message_content.as_bytes());
                let message_hash_bytes = hasher.finalize();
                let message_hash_hex = hex::encode(message_hash_bytes);

                let mut initial_signatures = HashSet::new();
                let local_peer_id_str_clone = local_peer_id_str.clone(); // Clone for use in SignedMessage
                initial_signatures.insert(local_peer_id_str_clone.clone()); // Use cloned peer_id_str

                let signed_message = SignedMessage {
                    content: message_content.to_string(),
                    originator_id: local_peer_id_str_clone.clone(), // Use cloned peer_id_str
                    message_hash: message_hash_hex.clone(),
                    signatures: initial_signatures,
                    sensor_readings: plain_data.sensor_readings,
                    power_readings: plain_data.power_readings,
                    location: plain_data.location,
                    timestamp: timestamp,
                };

                // Directly process and publish the message
                let mut store = message_store_clone.lock().unwrap();
                if !store.contains_key(&signed_message.message_hash) {
                    store.insert(signed_message.message_hash.clone(), signed_message.clone());
                    drop(store); // Release lock before async operations

                    match serde_json::to_string(&signed_message) {
                        Ok(json_message) => {
                            if let Err(e) = swarm
                                .behaviour_mut().gossipsub
                                .publish(topic.clone(), json_message.as_bytes())
                            {
                                eprintln!("Publish error for new message: {e:?}. Queuing for retry.");
                                failed_publish_queue_clone.lock().unwrap().push_back(signed_message);
                            } else {
                                write_log(
                                    &log_file_inner_clone,
                                    format!("MSG_PUBLISH_NEW Node={} Hash={} Content='{}'", 
                                        local_peer_id_str, signed_message.message_hash, signed_message.content)
                                ).await;
                                println!("Published new signed message: Hash {}", signed_message.message_hash);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error serializing new message: {}. Queuing for retry.", e);
                            failed_publish_queue_clone.lock().unwrap().push_back(signed_message);
                        }
                    }
                } else {
                    // Message with this hash already exists, perhaps from another node or a previous attempt.
                    // Depending on desired logic, you might want to log this or handle it differently.
                    // For now, we assume if it's in the store, it's being handled or was already published.
                    println!("Message hash {} already in store, not republishing immediately from creation.", signed_message.message_hash);
                }
            }
            
            // Handle retry publication
            _ = retry_publish_interval.tick() => {
                let mut queue = failed_publish_queue_clone.lock().unwrap();
                if !queue.is_empty() {
                    println!("Retrying publication for {} queued messages.", queue.len());
                    let mut still_failed = VecDeque::new(); // Collect messages that fail again
                    while let Some(message_to_retry) = queue.pop_front() {
                        match serde_json::to_string(&message_to_retry) {
                            Ok(json_message) => {
                                if let Err(e) = swarm
                                    .behaviour_mut().gossipsub
                                    .publish(topic.clone(), json_message.as_bytes())
                                {
                                    println!("Retry publish error for hash {}: {e:?}. Re-queuing.", message_to_retry.message_hash);
                                    still_failed.push_back(message_to_retry); // Add back if publish fails
                                } else {
                                    println!("Retry publish successful for hash {}.", message_to_retry.message_hash);
                                }
                            }
                            Err(e) => {
                                println!("Retry serialization error for hash {}: {}. Re-queuing.", message_to_retry.message_hash, e);
                                still_failed.push_back(message_to_retry); // Add back if serialization fails
                            }
                        }
                    }
                    // Put messages that failed again back into the main queue
                    queue.extend(still_failed);
                }
            }
            
            // Network metrics logging
            _ = metrics_interval.tick() => {
                let mut metrics = metrics_clone.lock().unwrap();
                let mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).count();
                
                // Add current mesh peer count to the history
                metrics.mesh_peer_counts.push(mesh_peers);
                
                // Calculate average connection duration
                let avg_connection_duration = if !metrics.connection_durations.is_empty() {
                    metrics.connection_durations.iter().sum::<Duration>() / metrics.connection_durations.len() as u32
                } else {
                    Duration::from_secs(0)
                };
                
                // Calculate average message latency
                let avg_message_latency = if !metrics.message_latencies.is_empty() {
                    metrics.message_latencies.iter().sum::<Duration>() / metrics.message_latencies.len() as u32
                } else {
                    Duration::from_secs(0)
                };
                
                // Calculate average mesh peer count
                let avg_mesh_peers = if !metrics.mesh_peer_counts.is_empty() {
                    metrics.mesh_peer_counts.iter().sum::<usize>() / metrics.mesh_peer_counts.len()
                } else {
                    0
                };
                
                // Log network metrics
                println!("\n=== Network Metrics ===");
                println!("Connection Success Rate: {:.2}%", 
                    (metrics.successful_connections as f64 / metrics.connection_attempts as f64) * 100.0);
                println!("Last Heartbeat: {:?}", metrics.last_heartbeat_time);
                println!("=====================\n");
            }
            
            // Connection retry handling
            _ = connection_retry_interval.tick() => {
                let mut retry_list = retry_list_clone.lock().unwrap();
                if !retry_list.is_empty() {
                    println!("Attempting to redial {} peers from retry list", retry_list.len());
                    
                    // Make a copy of the retry list
                    let mut retry_peers = Vec::new();
                    let now = SystemTime::now();
                    
                    // Process each peer in the retry list
                    retry_list.retain(|peer| {
                        // Only retry if last attempt was more than 10 seconds ago
                        // and less than 5 retry attempts have been made
                        let elapsed = now.duration_since(peer.last_attempt).unwrap_or(Duration::from_secs(0));
                        if elapsed >= Duration::from_secs(10) && peer.retry_count < 5 {
                            retry_peers.push(peer.clone());
                            true // Keep in the list for potential future retries
                        } else if peer.retry_count >= 5 {
                            println!("Removing peer {} from retry list after {} attempts", 
                                    peer.peer_id, peer.retry_count);
                            false // Remove from list if max retries reached
                        } else {
                            true // Keep in list but don't retry yet
                        }
                    });
                    
                    // Drop the lock before attempting to dial
                    drop(retry_list);
                    
                    // Attempt to dial each peer
                    for mut peer in retry_peers {
                        println!("Retrying connection to peer: {} (attempt {})", 
                                peer.peer_id, peer.retry_count + 1);
                        
                        match swarm.dial(peer.multiaddr.clone()) {
                            Ok(_) => {
                                println!("Retry dial initiated for peer: {}", peer.peer_id);
                                // Update retry count and last attempt time
                                peer.retry_count += 1;
                                peer.last_attempt = now;
                                
                                // Update the peer in the retry list
                                let mut retry_list = retry_list_clone.lock().unwrap();
                                if let Some(existing_peer) = retry_list.iter_mut()
                                    .find(|p| p.peer_id == peer.peer_id) {
                                    existing_peer.retry_count = peer.retry_count;
                                    existing_peer.last_attempt = peer.last_attempt;
                                }
                            }
                            Err(e) => {
                                println!("Retry dial failed for peer {}: {}", peer.peer_id, e);
                                // Update the retry count and last attempt anyway
                                peer.retry_count += 1;
                                peer.last_attempt = now;
                                
                                // Update the peer in the retry list
                                let mut retry_list = retry_list_clone.lock().unwrap();
                                if let Some(existing_peer) = retry_list.iter_mut()
                                    .find(|p| p.peer_id == peer.peer_id) {
                                    existing_peer.retry_count = peer.retry_count;
                                    existing_peer.last_attempt = peer.last_attempt;
                                }
                            }
                        }
                    }
                }
            }

            // Periodic devices.yaml sync
            _ = devices_sync_interval.tick() => {
                // Use the existing agent_for_sync, canister_id_for_sync, and config_devices_for_sync
                match devices_yaml::fetch_and_save_devices_yaml(&agent_for_sync, &canister_id_for_sync).await {
                    Ok(_) => {
                        
                        // Directly perform the reload logic. This part is blocking for file I/O.
                        match File::open("devices.yaml") { // std::fs::File, blocking
                            Ok(file) => {
                                match serde_yaml::from_reader::<_, Config>(file) { // blocking
                                    Ok(new_devices_config) => {
                                        let mut guard = config_devices_for_sync.lock().unwrap(); // Use the existing Arc<Mutex<Config>>
                                        *guard = new_devices_config;
                                    }
                                    Err(e) => {
                                        eprintln!("[SYNC_TASK] Failed to parse updated devices.yaml for reloading: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[SYNC_TASK] Failed to open updated devices.yaml for reloading: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[SYNC_TASK] Error during periodic sync (fetch_and_save_devices_yaml): {}", e);
                    }
                }
            }
        }
    }
}

// Function to submit verified data to blockchain
async fn submit_to_blockchain(
    verified_data: &VerifiedData, 
    device_id: &str, // This is originator_id
    config_devices: &Arc<Mutex<Config>>
) -> Result<String, Box<dyn Error>> {
    println!("[Blockchain] Attempting to submit data for device_id: {}", device_id);

    // Get device configuration FIRST to minimize lock duration
    println!("[Blockchain] Locking devices config to get device_type for device_id: {}", device_id);
    let device_type_from_config: String;
    let node_name_from_config: String; // For potential richer logging/data
    {
        let locked_devices_config = config_devices.lock().unwrap();
        let device_config = locked_devices_config.get_device_by_peer_id(device_id)
            .ok_or_else(|| {
                let err_msg = format!("Device configuration not found for originator_id: {} in config_devices", device_id);
                eprintln!("[Blockchain] Error: {}", err_msg);
                io::Error::new(io::ErrorKind::NotFound, err_msg)
            })?;
        device_type_from_config = device_config.device_type.clone();
        node_name_from_config = device_config.node_name.clone(); // Example: get node_name too
        println!("[Blockchain] Successfully retrieved device_type: {} for node: {} (Peer ID: {})", 
                 device_type_from_config, node_name_from_config, device_id);
    } // lock is released here

    // Initialize blockchain client
    println!("[Blockchain] Initializing BlockchainClient...");
    match BlockchainClient::new().await {
        Ok(client) => {
            println!("[Blockchain] BlockchainClient initialized successfully for device: {}", device_id);

            // Create a modified copy of power readings based on device type
            let mut modified_power_readings = verified_data.power_readings.clone();
            
            println!("[Blockchain] Modifying power readings based on device_type: {} for device_id: {}", device_type_from_config, device_id);
            match device_type_from_config.as_str() {
                "Solar Generator" => {
                    println!("[Blockchain] Submitting generated power data for Solar Generator (Peer ID: {})", device_id);
                },
                "Solar Consumer" => {
                    modified_power_readings.power_produced_kwh = modified_power_readings.power_consumed_kwh;
                    println!("[Blockchain] Submitting consumed power data for Solar Consumer (Peer ID: {})", device_id);
                },
                _ => {
                    println!("[Blockchain] Unknown device type: {}. Using default power readings for Peer ID: {}.", device_type_from_config, device_id);
                }
            }

            // Submit the data to blockchain with modified power readings
            println!("[Blockchain] Calling submit_energy_data_batch for device_id: {}", device_id);
            match client.submit_energy_data_batch(
                device_id,
                &modified_power_readings,
                &verified_data.sensor_readings,
                &verified_data.location
            ).await {
                Ok(tx_hash) => {
                    println!("[Blockchain] Successfully submitted data to blockchain for device_id: {}. Transaction hash: {}", device_id, tx_hash);
                    
                    // Start a background task to monitor the batch and process it when ready
                    let batch_hash = tx_hash;
                    let blockchain_client = client;
                    let owned_device_id = device_id.to_string(); // Create an owned String
                    
                    println!("[Blockchain] Spawning task to monitor batch {} for device_id: {}", batch_hash, owned_device_id);
                    tokio::spawn(async move {
                        println!("[BlockchainTask] Started monitoring batch {} for verification period (device_id: {})", batch_hash, owned_device_id);
                        // Wait for the batch processing delay (e.g., 10 minutes)
                        // This delay is configured in the smart contract
                        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
                        println!("[BlockchainTask] Finished waiting for batch {} (device_id: {}). Checking if processable.", batch_hash, owned_device_id);
                        
                        // Check if the batch is ready to be processed
                        match blockchain_client.is_batch_processable(batch_hash).await {
                            Ok(true) => {
                                println!("[BlockchainTask] Batch {} (device_id: {}) is ready for processing. Attempting to process.", batch_hash, owned_device_id);
                                match blockchain_client.process_batch(batch_hash).await {
                                    Ok(receipt) => println!("[BlockchainTask] Batch {} (device_id: {}) processed successfully: tx={}", batch_hash, owned_device_id, receipt.transaction_hash),
                                    Err(e) => eprintln!("[BlockchainTask] Failed to process batch {} (device_id: {}): {}", batch_hash, owned_device_id, e),
                                }
                            },
                            Ok(false) => println!("[BlockchainTask] Batch {} (device_id: {}) is not ready for processing yet.", batch_hash, owned_device_id),
                            Err(e) => eprintln!("[BlockchainTask] Error checking batch status for {} (device_id: {}): {}", batch_hash, owned_device_id, e),
                        }
                    });
                    
                    Ok(tx_hash.to_string()) // Return the transaction hash string
                },
                Err(e) => {
                    // Convert anyhow::Error to std::error::Error
                    let err_string = format!("[Blockchain] Blockchain error for device_id: {}: {}", device_id, e);
                    eprintln!("{}", err_string);
                    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, err_string)))
                }
            }
        },
        Err(e) => {
            // Convert anyhow::Error to std::error::Error
            let err_string = format!("[Blockchain] Blockchain client initialization error: {}", e);
            eprintln!("{}", err_string);
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, err_string)))
        }
    }
}



