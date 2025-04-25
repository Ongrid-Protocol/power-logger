use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::config::DeviceConfig;
use std::time::{SystemTime, UNIX_EPOCH};

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
        
        // Get current time for daylight simulation
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Temperature readings
        let temperature1 = rng.gen_range(20.0..30.0);
        let temperature2 = rng.gen_range(25.0..35.0);
        
        // Light sensor readings with time of day and weather simulation
        let (ldr_value, ldr_voltage, ldr_intensity) = if device_config.sensors.iter().any(|s| s.sensor_type == "light") {
            // Simulate time of day effect (0 to 24 hour cycle)
            let hour_of_day = (timestamp / 3600) % 24;
            
            // Daylight factor (0.0 to 1.0)
            // Peak at noon (hour 12), low at night
            let daylight_factor = if hour_of_day >= 6 && hour_of_day <= 18 {
                // Daytime: Use sine wave to simulate daylight intensity
                let hour_normalized = (hour_of_day as f32 - 6.0) / 12.0; // 0.0 to 1.0 range
                (std::f32::consts::PI * hour_normalized).sin()
            } else {
                // Nighttime: Very low light
                0.05
            };
            
            // Weather simulation (random weather conditions)
            let weather_condition = rng.gen_range(0..100);
            let weather_factor = match weather_condition {
                0..=20 => {
                    // Cloudy (20% chance)
                    rng.gen_range(0.3..0.5)
                },
                21..=30 => {
                    // Rainy (10% chance)
                    rng.gen_range(0.1..0.3)
                },
                31..=33 => {
                    // Very stormy (3% chance)
                    rng.gen_range(0.05..0.15)
                },
                _ => {
                    // Clear sky (67% chance)
                    rng.gen_range(0.8..1.0)
                }
            };
            
            // Combine factors for final light intensity
            let combined_factor = daylight_factor * weather_factor;
            
            // Scale to LDR values
            let value = (combined_factor * 1024.0) as i32;
            let voltage = combined_factor * 5.0;
            
            // Determine intensity label
            let intensity = match value {
                0..=200 => "Low".to_string(),
                201..=500 => "Medium".to_string(),
                _ => "High".to_string(),
            };
            
            (value, voltage, intensity)
        } else {
            (0, 0.0, "None".to_string())
        };

        // Current readings based on device specifications
        let max_current = device_config.specifications.max_wattage as f32 / 240.0 * 1000.0;

        // Scale currents based on light intensity to simulate solar panel behavior
        let current_scale_factor = match ldr_intensity.as_str() {
            "Low" => rng.gen_range(0.0..0.2),
            "Medium" => rng.gen_range(0.3..0.7),
            "High" => rng.gen_range(0.7..1.0),
            _ => 0.0,
        };
        
        // Apply current scaling
        let current_ma = [
            rng.gen_range(0.0..max_current) * current_scale_factor,
            rng.gen_range(0.0..max_current) * current_scale_factor,
            rng.gen_range(0.0..max_current) * current_scale_factor,
            rng.gen_range(0.0..max_current) * current_scale_factor,
        ];

        // Voltage readings - these remain relatively stable regardless of light
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