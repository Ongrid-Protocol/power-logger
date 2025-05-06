use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::config::{DeviceConfig, SensorConfig};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SensorReadings {
    pub temperature1: f64,
    pub temperature2: f64,
    pub ldr_value: i32,
    pub ldr_voltage: f64,
    pub ldr_intensity: String,
    pub current_ma: Vec<f64>,
    pub voltage_mv: Vec<f64>,
}

impl SensorReadings {
    pub fn new(device_config: &DeviceConfig) -> Self {
        let mut rng = rand::thread_rng();
        
        // Generate temperature readings within the configured range
        let temp_range = &device_config.sensors.temperature;
        let temperature1 = rng.gen_range(temp_range.min as f64..temp_range.max as f64);
        let temperature2 = rng.gen_range(temp_range.min as f64..temp_range.max as f64);
        
        // Generate light sensor readings
        let light_range = &device_config.sensors.light;
        let ldr_value = rng.gen_range(light_range.min..light_range.max);
        let ldr_voltage = (ldr_value as f64 / light_range.max as f64) * 3.3; // Assuming 3.3V reference
        let ldr_intensity = match ldr_value {
            0..=200 => "Dark".to_string(),
            201..=400 => "Dim".to_string(),
            401..=600 => "Normal".to_string(),
            601..=800 => "Bright".to_string(),
            _ => "Very Bright".to_string(),
        };
        
        // Generate current readings
        let current_range = &device_config.sensors.current;
        let current_ma = vec![
            rng.gen_range(current_range.min as f64..current_range.max as f64),
            rng.gen_range(current_range.min as f64..current_range.max as f64),
            rng.gen_range(current_range.min as f64..current_range.max as f64),
        ];
        
        // Generate voltage readings
        let voltage_range = &device_config.sensors.voltage;
        let voltage_mv = vec![
            rng.gen_range(voltage_range.min as f64..voltage_range.max as f64),
            rng.gen_range(voltage_range.min as f64..voltage_range.max as f64),
            rng.gen_range(voltage_range.min as f64..voltage_range.max as f64),
        ];
        
        Self {
            temperature1,
            temperature2,
            ldr_value,
            ldr_voltage,
            ldr_intensity,
            current_ma,
            voltage_mv,
        }
    }

    pub fn validate(&self, device_config: &DeviceConfig) -> bool {
        // Validate temperature ranges
        if self.temperature1 < device_config.sensors.temperature.min as f64 || self.temperature1 > device_config.sensors.temperature.max as f64 ||
           self.temperature2 < device_config.sensors.temperature.min as f64 || self.temperature2 > device_config.sensors.temperature.max as f64 {
            return false;
        }

        // Validate light sensor if present
        if device_config.sensors.light.min != 0 || device_config.sensors.light.max != 1024 {
            if self.ldr_value < device_config.sensors.light.min || self.ldr_value > device_config.sensors.light.max ||
               self.ldr_voltage < 0.0 || self.ldr_voltage > 3.3 {
                return false;
            }
        }

        // Validate current readings
        let current_range = &device_config.sensors.current;
        for &current in &self.current_ma {
            if current < current_range.min as f64 || current > current_range.max as f64 {
                return false;
            }
        }

        // Validate voltage readings
        let voltage_range = &device_config.sensors.voltage;
        for &voltage in &self.voltage_mv {
            if voltage < voltage_range.min as f64 || voltage > voltage_range.max as f64 {
                return false;
            }
        }

        true
    }
} 