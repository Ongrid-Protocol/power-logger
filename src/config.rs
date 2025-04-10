use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use crate::gps::Location;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub location: DeviceLocation,
    pub specifications: DeviceSpecifications,
    pub sensors: Vec<SensorConfig>,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub country: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSpecifications {
    pub max_wattage: u32,
    pub voltage_range: String,
    pub frequency_range: String,
    pub battery_capacity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    pub sensor_type: String,
    pub count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    pub network: DefaultNetworkConfig,
    pub sensors: DefaultSensorConfig,
    pub logging: DefaultLoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultNetworkConfig {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSensorConfig {
    pub temperature: SensorDefaults,
    pub current: SensorDefaults,
    pub voltage: SensorDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorDefaults {
    pub sampling_rate: String,
    pub accuracy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultLoggingConfig {
    pub interval: String,
    pub format: String,
    pub retention: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub devices: Vec<DeviceConfig>,
    pub defaults: DefaultConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn get_device(&self, device_id: &str) -> Option<&DeviceConfig> {
        self.devices.iter().find(|d| d.id == device_id)
    }

    pub fn get_device_location(&self, device_id: &str) -> Option<Location> {
        self.get_device(device_id).map(|device| {
            Location::new(
                device.location.latitude,
                device.location.longitude,
                0.0, // Default altitude
                5.0, // Default accuracy
                8,   // Default satellite count
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_loading() {
        let path = PathBuf::from("config/devices.yaml");
        let config = Config::load(&path).unwrap();
        
        // Test device count
        assert_eq!(config.devices.len(), 3);
        
        // Test first device
        let device = config.get_device("RASPBERRY_PI_1").unwrap();
        assert_eq!(device.id, "RASPBERRY_PI_1");
        assert_eq!(device.name, "Solar Panel Controller 1");
        assert_eq!(device.device_type, "solar_controller");
        assert_eq!(device.location.country, "US");
        assert_eq!(device.specifications.max_wattage, 1000);
        
        // Test location conversion
        let location = config.get_device_location("RASPBERRY_PI_1").unwrap();
        assert_eq!(location.latitude, 40.7128);
        assert_eq!(location.longitude, -74.0060);
        assert!(location.is_valid());
    }
} 