use serde::{Deserialize, Serialize};
use anyhow::Result;
use deadpool_postgres::{Manager, Pool, Runtime};
use tokio_postgres::{NoTls, Config as PgConfig};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub message_hash: String,
    pub content: String,
    pub originator_id: String,
    pub timestamp: i64,
    pub signers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedData {
    pub message_hash: String,
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub contract_address: String,
    pub max_wattage: i32,
    pub voltage_range: String,
    pub frequency_range: String,
    pub battery_capacity: String,
    pub phase_type: String,
    pub timestamp: i64,
    pub sensor_readings: SensorReadings,
    pub power_readings: PowerReadings,
    pub location: Location,
    pub verification_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorReadings {
    pub temperature: f64,
    pub light: i32,
    pub current: i32,
    pub voltage: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerReadings {
    pub generated: f64,
    pub consumed: f64,
    pub battery_level: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: f64,
    pub country: Country,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Country {
    pub code: String,
    pub name: String,
    pub region: String,
}

pub struct Database {
    pool: Pool,
}

impl Database {
    pub async fn new() -> Result<Self> {
        let mut cfg = PgConfig::new();
        cfg.host(env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string()));
        cfg.port(env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string()).parse()?);
        cfg.dbname(env::var("POSTGRES_DB").unwrap_or_else(|_| "power_logger".to_string()));
        cfg.user(env::var("POSTGRES_USER").unwrap_or_else(|_| "power_logger_user".to_string()));
        cfg.password(env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "".to_string()));

        let mgr = Manager::new(cfg, NoTls);
        let pool = Pool::builder(mgr)
            .runtime(Runtime::Tokio1)
            .build()?;

        Ok(Self { pool })
    }

    pub async fn store_message(&self, message: &Message) -> Result<()> {
        let mut client = self.pool.get().await?;
        
        // Start a transaction
        let transaction = client.transaction().await?;

        // Insert the message
        transaction.execute(
            "INSERT INTO messages (message_hash, content, originator_id, timestamp)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (message_hash) DO NOTHING",
            &[
                &message.message_hash,
                &message.content,
                &message.originator_id,
                &message.timestamp,
            ],
        ).await?;

        // Insert all signers
        for signer_id in &message.signers {
            transaction.execute(
                "INSERT INTO message_signers (message_hash, signer_id)
                 VALUES ($1, $2)
                 ON CONFLICT (message_hash, signer_id) DO NOTHING",
                &[&message.message_hash, signer_id],
            ).await?;
        }

        // Commit the transaction
        transaction.commit().await?;

        Ok(())
    }

    pub async fn add_signer(&self, message_hash: &str, signer_id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        
        client.execute(
            "INSERT INTO message_signers (message_hash, signer_id)
             VALUES ($1, $2)
             ON CONFLICT (message_hash, signer_id) DO NOTHING",
            &[&message_hash, &signer_id],
        ).await?;

        Ok(())
    }

    pub async fn get_message_signers(&self, message_hash: &str) -> Result<Vec<String>> {
        let client = self.pool.get().await?;
        
        let rows = client.query(
            "SELECT signer_id FROM message_signers WHERE message_hash = $1",
            &[&message_hash],
        ).await?;

        let signers = rows.iter()
            .map(|row| row.get::<_, String>("signer_id"))
            .collect();

        Ok(signers)
    }

    pub async fn save_verified_data(&self, data: &VerifiedData) -> Result<()> {
        let mut client = self.pool.get().await?;
        
        // Start a transaction
        let transaction = client.transaction().await?;

        // First, ensure device exists
        transaction.execute(
            "INSERT INTO devices (id, name, device_type, contract_address, max_wattage, voltage_range, frequency_range, battery_capacity, phase_type)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             device_type = EXCLUDED.device_type,
             contract_address = EXCLUDED.contract_address,
             max_wattage = EXCLUDED.max_wattage,
             voltage_range = EXCLUDED.voltage_range,
             frequency_range = EXCLUDED.frequency_range,
             battery_capacity = EXCLUDED.battery_capacity,
             phase_type = EXCLUDED.phase_type",
            &[
                &data.device_id,
                &data.device_name,
                &data.device_type,
                &data.contract_address,
                &data.max_wattage,
                &data.voltage_range,
                &data.frequency_range,
                &data.battery_capacity,
                &data.phase_type,
            ],
        ).await?;

        // Then, ensure location exists
        transaction.execute(
            "INSERT INTO locations (device_id, latitude, longitude, altitude, country_code, country_name, region)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (device_id) DO UPDATE SET
             latitude = EXCLUDED.latitude,
             longitude = EXCLUDED.longitude,
             altitude = EXCLUDED.altitude,
             country_code = EXCLUDED.country_code,
             country_name = EXCLUDED.country_name,
             region = EXCLUDED.region",
            &[
                &data.device_id,
                &data.location.latitude,
                &data.location.longitude,
                &data.location.altitude,
                &data.location.country.code,
                &data.location.country.name,
                &data.location.country.region,
            ],
        ).await?;

        // Finally, insert the verified data
        transaction.execute(
            "INSERT INTO verified_data (
                message_hash, device_id, timestamp, temperature, light, current, voltage,
                power_generated, power_consumed, battery_level, verification_count
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &data.message_hash,
                &data.device_id,
                &data.timestamp,
                &data.sensor_readings.temperature,
                &data.sensor_readings.light,
                &data.sensor_readings.current,
                &data.sensor_readings.voltage,
                &data.power_readings.generated,
                &data.power_readings.consumed,
                &data.power_readings.battery_level,
                &data.verification_count,
            ],
        ).await?;

        // Commit the transaction
        transaction.commit().await?;

        Ok(())
    }

    pub async fn get_device_stats(&self, device_id: &str, start_time: i64, end_time: i64) -> Result<DeviceStats> {
        let client = self.pool.get().await?;
        
        let row = client.query_one(
            "SELECT 
                AVG(power_generated) as avg_generated,
                MAX(power_generated) as max_generated,
                MIN(power_generated) as min_generated,
                SUM(power_generated) as total_generated,
                AVG(power_consumed) as avg_consumed,
                MAX(power_consumed) as max_consumed,
                MIN(power_consumed) as min_consumed,
                SUM(power_consumed) as total_consumed,
                AVG(battery_level) as avg_battery,
                COUNT(DISTINCT ms.signer_id) as avg_signers
             FROM verified_data vd
             JOIN messages m ON vd.message_hash = m.message_hash
             JOIN message_signers ms ON m.message_hash = ms.message_hash
             WHERE vd.device_id = $1 AND vd.timestamp BETWEEN $2 AND $3
             GROUP BY vd.device_id",
            &[&device_id, &start_time, &end_time],
        ).await?;

        Ok(DeviceStats {
            avg_generated: row.get("avg_generated"),
            max_generated: row.get("max_generated"),
            min_generated: row.get("min_generated"),
            total_generated: row.get("total_generated"),
            avg_consumed: row.get("avg_consumed"),
            max_consumed: row.get("max_consumed"),
            min_consumed: row.get("min_consumed"),
            total_consumed: row.get("total_consumed"),
            avg_battery: row.get("avg_battery"),
            avg_signers: row.get("avg_signers"),
        })
    }

    pub async fn get_region_stats(&self, region: &str, start_time: i64, end_time: i64) -> Result<RegionStats> {
        let client = self.pool.get().await?;
        
        let row = client.query_one(
            "SELECT 
                COUNT(DISTINCT vd.device_id) as device_count,
                AVG(vd.power_generated) as avg_generated,
                SUM(vd.power_generated) as total_generated,
                AVG(vd.power_consumed) as avg_consumed,
                SUM(vd.power_consumed) as total_consumed,
                COUNT(DISTINCT ms.signer_id) as total_signers
             FROM verified_data vd
             JOIN locations l ON vd.device_id = l.device_id
             JOIN messages m ON vd.message_hash = m.message_hash
             JOIN message_signers ms ON m.message_hash = ms.message_hash
             WHERE l.region = $1 AND vd.timestamp BETWEEN $2 AND $3
             GROUP BY l.region",
            &[&region, &start_time, &end_time],
        ).await?;

        Ok(RegionStats {
            device_count: row.get("device_count"),
            avg_generated: row.get("avg_generated"),
            total_generated: row.get("total_generated"),
            avg_consumed: row.get("avg_consumed"),
            total_consumed: row.get("total_consumed"),
            total_signers: row.get("total_signers"),
        })
    }
}

#[derive(Debug)]
pub struct DeviceStats {
    pub avg_generated: f64,
    pub max_generated: f64,
    pub min_generated: f64,
    pub total_generated: f64,
    pub avg_consumed: f64,
    pub max_consumed: f64,
    pub min_consumed: f64,
    pub total_consumed: f64,
    pub avg_battery: f64,
    pub avg_signers: i64,
}

#[derive(Debug)]
pub struct RegionStats {
    pub device_count: i64,
    pub avg_generated: f64,
    pub total_generated: f64,
    pub avg_consumed: f64,
    pub total_consumed: f64,
    pub total_signers: i64,
} 