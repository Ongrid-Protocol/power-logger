use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::config::DeviceConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorReadings {
    pub temperature1: f32,
    pub temperature2: f32,
    pub ldr_value: i32,
    pub ldr_voltage: f32,
    pub ldr_intensity: String,
    pub current_ma: [f32; 4],
    pub voltage_mv: [f32; 4],
}

impl SensorReadings {
    pub fn new(device_config: &DeviceConfig) -> Self {
        let mut rng = rand::thread_rng();
        
        // Temperature readings
        let temperature1 = rng.gen_range(20.0..30.0);
        let temperature2 = rng.gen_range(25.0..35.0);
        
        // Light sensor readings
        let (ldr_value, ldr_voltage) = if device_config.sensors.iter().any(|s| s.sensor_type == "light") {
            let value = rng.gen_range(0..1024);
            let voltage = rng.gen_range(0.0..5.0);
            (value, voltage)
        } else {
            (0, 0.0)
        };
        
        let ldr_intensity = match ldr_value {
            0..=200 => "Low".to_string(),
            201..=500 => "Medium".to_string(),
            _ => "High".to_string(),
        };

        // Current readings based on device specifications
        let max_current = device_config.specifications.max_wattage as f32 / 240.0 * 1000.0;
        let current_ma = [
            rng.gen_range(0.0..max_current),
            rng.gen_range(0.0..max_current),
            rng.gen_range(0.0..max_current),
            rng.gen_range(0.0..max_current),
        ];

        // Voltage readings
        let voltage_mv = [
            rng.gen_range(220000.0..240000.0),
            rng.gen_range(220000.0..240000.0),
            rng.gen_range(220000.0..240000.0),
            rng.gen_range(220000.0..240000.0),
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
        if self.temperature1 < 0.0 || self.temperature1 > 100.0 ||
           self.temperature2 < 0.0 || self.temperature2 > 100.0 {
            return false;
        }

        // Validate light sensor if present
        if device_config.sensors.iter().any(|s| s.sensor_type == "light") {
            if self.ldr_value < 0 || self.ldr_value > 1024 ||
               self.ldr_voltage < 0.0 || self.ldr_voltage > 5.0 {
                return false;
            }
        }

        // Validate current readings
        let max_current = device_config.specifications.max_wattage as f32 / 240.0 * 1000.0;
        for &current in &self.current_ma {
            if current < 0.0 || current > max_current {
                return false;
            }
        }

        // Validate voltage readings
        for &voltage in &self.voltage_mv {
            if voltage < 220000.0 || voltage > 240000.0 {
                return false;
            }
        }

        true
    }
} 