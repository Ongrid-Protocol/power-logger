use lapin::{Connection, ConnectionProperties};
use tokio::sync::OnceCell;
use std::sync::Arc;
use anyhow::Result;
use crate::sensors::SensorReadings;
use crate::power::PowerReadings;
use crate::gps::Location;
use serde::{Serialize, Deserialize};
use lapin::options::BasicPublishOptions;
use lapin::BasicProperties;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedData {
    pub message_hash: String,
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub wallet_address: String,
    pub max_wattage: u32,
    pub voltage_range: String,
    pub frequency_range: String,
    pub battery_capacity: String,
    pub phase_type: String,
    pub timestamp: u64,
    pub sensor_readings: SensorReadings,
    pub power_readings: PowerReadings,
    pub location: Location,
    pub verified_by: Vec<String>,
    pub verification_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Country {
    pub code: String,
    pub name: String,
    pub region: String,
}

pub struct RabbitMQClient {
    connection: Connection,
}

impl RabbitMQClient {
    pub async fn get_client() -> Result<Self> {
        let connection = Connection::connect(
            "amqp://guest:guest@localhost:5672",
            ConnectionProperties::default(),
        ).await?;

        Ok(Self {
            connection,
        })
    }

    pub async fn publish_verified_data(
        &self,
        data: VerifiedData,
        exchange: &str,
        routing_key: &str,
    ) -> Result<()> {
        let channel = self.connection.create_channel().await?;
        
        let data_json = serde_json::to_string(&data)?;
        
        channel.basic_publish(
            exchange,
            routing_key,
            BasicPublishOptions::default(),
            data_json.as_bytes(),
            BasicProperties::default(),
        ).await?;

        Ok(())
    }
} 