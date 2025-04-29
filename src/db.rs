use sqlx::{postgres::PgPoolOptions, PgPool, Error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerData {
    pub timestamp: u64,
    pub sensor_readings: SensorReadings,
    pub power_readings: PowerReadings,
    pub device_id: String,
    pub location: Location,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorReadings {
    pub temperature1: f64,
    pub temperature2: f64,
    pub ldr_value: i32,
    pub ldr_voltage: f64,
    pub ldr_intensity: String,
    pub current_ma: Vec<f64>,
    pub voltage_mv: Vec<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerReadings {
    pub power_produced: f64,
    pub battery_storage: f64,
    pub power_consumed: f64,
    pub device_consumption: f64,
    pub power_produced_kwh: f64,
    pub battery_storage_kwh: f64,
    pub power_consumed_kwh: f64,
    pub device_consumption_kwh: f64,
    pub ac_voltage: f64,
    pub ac_current: f64,
    pub ac_power: f64,
    pub ac_energy: f64,
    pub ac_frequency: f64,
    pub ac_power_factor: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: f64,
    pub timestamp: u64,
    pub accuracy: f64,
    pub satellites: i32,
    pub country: Country,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Country {
    pub code: String,
    pub name: String,
    pub region: String,
}

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        Ok(Database { pool })
    }

    pub async fn store_verified_data(&self, data: &PowerData, verified_by: Vec<String>) -> Result<(), Error> {
        let mut transaction = self.pool.begin().await?;

        // Insert device if not exists
        sqlx::query!(
            r#"
            INSERT INTO devices (device_id, name)
            VALUES ($1, $2)
            ON CONFLICT (device_id) DO NOTHING
            "#,
            data.device_id,
            data.device_id // Using device_id as name for now
        )
        .execute(&mut transaction)
        .await?;

        // Insert location
        let location_id = sqlx::query!(
            r#"
            INSERT INTO locations (
                device_id, latitude, longitude, altitude, accuracy,
                satellites, country_code, country_name, region, timestamp
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
            "#,
            data.device_id,
            data.location.latitude,
            data.location.longitude,
            data.location.altitude,
            data.location.accuracy,
            data.location.satellites,
            data.location.country.code,
            data.location.country.name,
            data.location.country.region,
            data.location.timestamp as i64
        )
        .fetch_one(&mut transaction)
        .await?
        .id;

        // Insert sensor readings
        let sensor_id = sqlx::query!(
            r#"
            INSERT INTO sensor_readings (
                device_id, timestamp, temperature1, temperature2,
                ldr_value, ldr_voltage, ldr_intensity, current_ma, voltage_mv
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
            data.device_id,
            data.timestamp as i64,
            data.sensor_readings.temperature1,
            data.sensor_readings.temperature2,
            data.sensor_readings.ldr_value,
            data.sensor_readings.ldr_voltage,
            data.sensor_readings.ldr_intensity,
            &data.sensor_readings.current_ma,
            &data.sensor_readings.voltage_mv
        )
        .fetch_one(&mut transaction)
        .await?
        .id;

        // Insert power readings
        let power_id = sqlx::query!(
            r#"
            INSERT INTO power_readings (
                device_id, timestamp, power_produced, battery_storage,
                power_consumed, device_consumption, power_produced_kwh,
                battery_storage_kwh, power_consumed_kwh, device_consumption_kwh,
                ac_voltage, ac_current, ac_power, ac_energy, ac_frequency, ac_power_factor
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING id
            "#,
            data.device_id,
            data.timestamp as i64,
            data.power_readings.power_produced,
            data.power_readings.battery_storage,
            data.power_readings.power_consumed,
            data.power_readings.device_consumption,
            data.power_readings.power_produced_kwh,
            data.power_readings.battery_storage_kwh,
            data.power_readings.power_consumed_kwh,
            data.power_readings.device_consumption_kwh,
            data.power_readings.ac_voltage,
            data.power_readings.ac_current,
            data.power_readings.ac_power,
            data.power_readings.ac_energy,
            data.power_readings.ac_frequency,
            data.power_readings.ac_power_factor
        )
        .fetch_one(&mut transaction)
        .await?
        .id;

        // Insert verification record
        sqlx::query!(
            r#"
            INSERT INTO verifications (
                message_hash, device_id, timestamp, verified_by, verification_count
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::new_v4().to_string(), // Using UUID as message hash for now
            data.device_id,
            data.timestamp as i64,
            &verified_by,
            verified_by.len() as i32
        )
        .execute(&mut transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }
} 