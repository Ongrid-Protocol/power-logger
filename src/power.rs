use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::config::DeviceConfig;
use crate::sensors::SensorReadings;

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
        
        // Create sensor readings first to get light intensity
        let sensor_readings = SensorReadings::new(device_config);
        
        // Parse voltage and frequency ranges from device specifications
        let voltage_range: Vec<f32> = device_config.specifications.voltage_range
            .split('-')
            .map(|v| v.trim_end_matches("V").parse().unwrap())
            .collect();
        
        let frequency_range: Vec<f32> = device_config.specifications.frequency_range
            .split('-')
            .map(|f| f.trim_end_matches("Hz").parse().unwrap())
            .collect();

        // Generate AC values - handle both range and single values
        let ac_voltage = if voltage_range.len() > 1 {
            rng.gen_range(voltage_range[0]..voltage_range[1])
        } else {
            // If only a single value is provided, use it with small variation
            voltage_range[0] * rng.gen_range(0.95..1.05)
        };
        
        let ac_frequency = if frequency_range.len() > 1 {
            rng.gen_range(frequency_range[0]..frequency_range[1])
        } else {
            // If only a single value is provided, use it with small variation
            frequency_range[0] * rng.gen_range(0.98..1.02)
        };
        
        let ac_power_factor = rng.gen_range(0.8..1.0);

        // Calculate power values based on device specifications AND light intensity
        let max_power = device_config.specifications.max_wattage as f32;
        
        // Calculate light efficiency factor (0.0 to 1.0)
        let light_efficiency = match sensor_readings.ldr_intensity.as_str() {
            "Low" => rng.gen_range(0.0..0.2),    // Very low power production
            "Medium" => rng.gen_range(0.3..0.7),  // Moderate power production
            "High" => rng.gen_range(0.7..1.0),    // High power production
            _ => 0.0,  // No light, no power
        };
        
        // Apply light efficiency to power production
        let power_produced = max_power * light_efficiency;
        
        // Other power calculations based on production
        let battery_storage = rng.gen_range(0.0..power_produced * 0.2);
        let power_consumed = rng.gen_range(0.0..power_produced * 0.7);
        let device_consumption = rng.gen_range(0.0..max_power * 0.1);

        // Calculate AC current and power based on production
        let ac_current = if power_produced > 0.0 {
            power_produced / (ac_voltage * ac_power_factor)
        } else {
            0.0
        };
        
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

    // Create a new method to generate power readings based on provided sensor readings
    pub fn new_with_sensors(device_config: &DeviceConfig, sensor_readings: &SensorReadings) -> Self {
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

        // Generate AC values - handle both range and single values
        let ac_voltage = if voltage_range.len() > 1 {
            rng.gen_range(voltage_range[0]..voltage_range[1])
        } else {
            // If only a single value is provided, use it with small variation
            voltage_range[0] * rng.gen_range(0.95..1.05)
        };
        
        let ac_frequency = if frequency_range.len() > 1 {
            rng.gen_range(frequency_range[0]..frequency_range[1])
        } else {
            // If only a single value is provided, use it with small variation
            frequency_range[0] * rng.gen_range(0.98..1.02)
        };
        
        let ac_power_factor = rng.gen_range(0.8..1.0);

        // Calculate power values based on device specifications AND light intensity
        let max_power = device_config.specifications.max_wattage as f32;
        
        // Calculate light efficiency factor (0.0 to 1.0)
        let light_efficiency = match sensor_readings.ldr_intensity.as_str() {
            "Low" => rng.gen_range(0.0..0.2),    // Very low power production
            "Medium" => rng.gen_range(0.3..0.7),  // Moderate power production
            "High" => rng.gen_range(0.7..1.0),    // High power production
            _ => 0.0,  // No light, no power
        };
        
        // Apply light efficiency to power production
        let power_produced = max_power * light_efficiency;
        
        // Other power calculations based on production
        let battery_storage = rng.gen_range(0.0..power_produced * 0.2);
        let power_consumed = rng.gen_range(0.0..power_produced * 0.7);
        let device_consumption = rng.gen_range(0.0..max_power * 0.1);

        // Calculate AC current and power based on production
        let ac_current = if power_produced > 0.0 {
            power_produced / (ac_voltage * ac_power_factor)
        } else {
            0.0
        };
        
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
           self.battery_storage < 0.0 || self.battery_storage > max_power * 0.2 ||
           self.power_consumed < 0.0 || self.power_consumed > self.power_produced ||
           self.device_consumption < 0.0 || self.device_consumption > max_power * 0.1 {
            return false;
        }

        // Validate AC values
        let min_voltage = voltage_range[0] * 0.95;
        let max_voltage = if voltage_range.len() > 1 { voltage_range[1] } else { voltage_range[0] * 1.05 };
        
        let min_frequency = frequency_range[0] * 0.98;
        let max_frequency = if frequency_range.len() > 1 { frequency_range[1] } else { frequency_range[0] * 1.02 };
        
        if self.ac_voltage < min_voltage || self.ac_voltage > max_voltage ||
           self.ac_frequency < min_frequency || self.ac_frequency > max_frequency ||
           self.ac_power_factor < 0.8 || self.ac_power_factor > 1.0 {
            return false;
        }

        true
    }
} 