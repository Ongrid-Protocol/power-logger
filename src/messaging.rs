use lapin::{Connection, ConnectionProperties, options::*, types::FieldTable, BasicProperties, message::Delivery};
use serde::{Serialize, Deserialize};
use tokio::sync::OnceCell;
use std::sync::Arc;
use anyhow::Result;
use tokio::runtime::Runtime;
use crate::sensors::SensorReadings;
use crate::power::PowerReadings;
use crate::gps::Location;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedData {
    pub device_id: String,
    pub wallet_address: String,
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
    runtime: Runtime,
}

static RABBITMQ_CLIENT: OnceCell<Arc<RabbitMQClient>> = OnceCell::const_new();

impl RabbitMQClient {
    pub async fn get_client() -> Result<Self> {
        let runtime = Runtime::new()?;
        let connection = Connection::connect(
            "amqp://guest:guest@localhost:5672",
            ConnectionProperties::default(),
        ).await?;

        Ok(Self {
            connection,
            runtime,
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