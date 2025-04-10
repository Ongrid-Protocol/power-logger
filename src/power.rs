use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::config::DeviceConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerReadings {
    pub power_produced: f32,
    pub battery_storage: f32,
    pub power_consumed: f32,
    pub device_consumption: f32,
    pub power_produced_kwh: f32,
    pub battery_storage_kwh: f32,
    pub power_consumed_kwh: f32,
    pub device_consumption_kwh: f32,
    pub ac_voltage: f32,
    pub ac_current: f32,
    pub ac_power: f32,
    pub ac_energy: f32,
    pub ac_frequency: f32,
    pub ac_power_factor: f32,
}

impl PowerReadings {
    pub fn new(device_config: &DeviceConfig) -> Self {
        let mut rng = rand::thread_rng();
        
        // Parse voltage and frequency ranges from device specifications
        let voltage_range: Vec<f32> = device_config.specifications.voltage_range
            .split('-')
            .map(|v| v.trim_end_matches("V").parse().unwrap())
            .collect();
        
        let frequency_range: Vec<f32> = device_config.specifications.frequency_range
            .split('-')
            .map(|f| f.trim_end_matches("Hz").parse().unwrap())
            .collect();

        // Generate AC values
        let ac_voltage = rng.gen_range(voltage_range[0]..voltage_range[1]);
        let ac_frequency = rng.gen_range(frequency_range[0]..frequency_range[1]);
        let ac_power_factor = rng.gen_range(0.8..1.0);

        // Calculate power values based on device specifications
        let max_power = device_config.specifications.max_wattage as f32;
        let power_produced = rng.gen_range(0.0..max_power);
        let battery_storage = rng.gen_range(0.0..max_power * 0.1);
        let power_consumed = rng.gen_range(0.0..max_power * 0.5);
        let device_consumption = rng.gen_range(0.0..max_power * 0.1);

        // Calculate AC current and power
        let ac_current = rng.gen_range(0.0..max_power / ac_voltage);
        let ac_power = ac_voltage * ac_current * ac_power_factor;
        let ac_energy = ac_power * 0.001; // Convert to kWh

        // Convert power values to kWh
        let power_produced_kwh = power_produced / 1000.0;
        let battery_storage_kwh = battery_storage / 1000.0;
        let power_consumed_kwh = power_consumed / 1000.0;
        let device_consumption_kwh = device_consumption / 1000.0;

        Self {
            power_produced,
            battery_storage,
            power_consumed,
            device_consumption,
            power_produced_kwh,
            battery_storage_kwh,
            power_consumed_kwh,
            device_consumption_kwh,
            ac_voltage,
            ac_current,
            ac_power,
            ac_energy,
            ac_frequency,
            ac_power_factor,
        }
    }

    pub fn validate(&self, device_config: &DeviceConfig) -> bool {
        let max_power = device_config.specifications.max_wattage as f32;
        
        // Parse voltage and frequency ranges
        let voltage_range: Vec<f32> = device_config.specifications.voltage_range
            .split('-')
            .map(|v| v.trim_end_matches("V").parse().unwrap())
            .collect();
        
        let frequency_range: Vec<f32> = device_config.specifications.frequency_range
            .split('-')
            .map(|f| f.trim_end_matches("Hz").parse().unwrap())
            .collect();

        // Validate power values
        if self.power_produced < 0.0 || self.power_produced > max_power ||
           self.battery_storage < 0.0 || self.battery_storage > max_power * 0.1 ||
           self.power_consumed < 0.0 || self.power_consumed > max_power * 0.5 ||
           self.device_consumption < 0.0 || self.device_consumption > max_power * 0.1 {
            return false;
        }

        // Validate AC values
        if self.ac_voltage < voltage_range[0] || self.ac_voltage > voltage_range[1] ||
           self.ac_frequency < frequency_range[0] || self.ac_frequency > frequency_range[1] ||
           self.ac_power_factor < 0.8 || self.ac_power_factor > 1.0 {
            return false;
        }

        true
    }
} 