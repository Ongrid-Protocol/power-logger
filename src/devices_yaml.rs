use std::error::Error;
use std::fs;
use ic_agent::Agent;
use candid::Principal;
use serde_yaml;
use power_logger::config::Config;

/// Fetches the devices.yaml content from the canister
pub async fn fetch_devices_yaml(agent: &Agent, canister_id: &Principal) -> Result<String, Box<dyn Error + Send + Sync>> {
    let response = agent
        .query(canister_id, "get_devices_yaml")
        .with_arg(candid::encode_args(())?)
        .call()
        .await?;

    let yaml_content: String = candid::decode_one(&response)?;
    Ok(yaml_content)
}

/// Fetches and saves the devices.yaml file
pub async fn fetch_and_save_devices_yaml(agent: &Agent, canister_id: &Principal) -> Result<(), Box<dyn Error + Send + Sync>> {
    let yaml_content = fetch_devices_yaml(agent, canister_id).await?;
    
    if yaml_content.is_empty() {
        return Err("Received empty devices.yaml from canister".into());
    }

    // Validate the YAML content by attempting to parse it
    let _config: Config = serde_yaml::from_str(&yaml_content)?;
    
    // Save to devices.yaml file
    fs::write("devices.yaml", yaml_content)?;
    println!("Successfully updated devices.yaml from canister");
    
    Ok(())
}

/// Gets the number of registered nodes
pub async fn get_registered_node_count(agent: &Agent, canister_id: &Principal) -> Result<usize, Box<dyn Error + Send + Sync>> {
    let response = agent
        .query(canister_id, "get_nodes")
        .with_arg(candid::encode_args(())?)
        .call()
        .await?;

    #[derive(candid::CandidType, candid::Deserialize)]
    struct Node {
        node_principal: Principal,
        multiaddress: String,
        last_heartbeat: u64,
    }

    let nodes: Vec<Node> = candid::decode_one(&response)?;
    Ok(nodes.len())
}

/// Determines if verification should start based on node count
pub async fn should_start_verification(agent: &Agent, canister_id: &Principal, min_nodes: usize) -> bool {
    match get_registered_node_count(agent, canister_id).await {
        Ok(count) => {
            let should_verify = count >= min_nodes;
            if !should_verify {
                println!("Only {} nodes registered. Verification requires at least {} nodes.",
                    count, min_nodes);
            } else {
                println!("{} nodes registered. Verification can proceed.", count);
            }
            should_verify
        },
        Err(e) => {
            println!("Error checking node count, defaulting to no verification: {}", e);
            false
        }
    }
}
