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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<DefaultNetworkConfig>,
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
            // Create the location
            let mut location = Location::new(
                device.location.latitude,
                device.location.longitude,
                0.0, // Default altitude
                5.0, // Default accuracy
                8,   // Default satellite count
            );
            
            // Manually set the country information from the device configuration
            // instead of trying to detect it, which only works for a few countries
            location.country = Some(crate::gps::Country {
                code: device.location.country.clone(),
                name: get_country_name(&device.location.country),
                region: device.location.region.clone(),
            });
            
            location
        })
    }
}

// Helper function to get country name from code
fn get_country_name(code: &str) -> String {
    match code {
        "US" => "United States",
        "CA" => "Canada",
        "MX" => "Mexico",
        "BR" => "Brazil",
        "AR" => "Argentina",
        "CL" => "Chile",
        "PE" => "Peru",
        "CO" => "Colombia",
        "EC" => "Ecuador",
        "GB" => "United Kingdom",
        "DE" => "Germany",
        "FR" => "France",
        "ES" => "Spain",
        "IT" => "Italy",
        "PT" => "Portugal",
        "CH" => "Switzerland",
        "AT" => "Austria",
        "SE" => "Sweden",
        "NO" => "Norway",
        "FI" => "Finland",
        "JP" => "Japan",
        "CN" => "China",
        "IN" => "India",
        "KR" => "South Korea",
        "SG" => "Singapore",
        "TH" => "Thailand",
        "ID" => "Indonesia",
        "MY" => "Malaysia",
        "VN" => "Vietnam",
        "PH" => "Philippines",
        "ZA" => "South Africa",
        "EG" => "Egypt",
        "NG" => "Nigeria",
        "KE" => "Kenya",
        "ET" => "Ethiopia",
        "TZ" => "Tanzania",
        "ML" => "Mali",
        "AU" => "Australia",
        "NZ" => "New Zealand",
        "FJ" => "Fiji",
        "PG" => "Papua New Guinea",
        "SB" => "Solomon Islands",
        "CR" => "Costa Rica",
        "PA" => "Panama",
        "DO" => "Dominican Republic",
        "UY" => "Uruguay",
        "PY" => "Paraguay",
        "BO" => "Bolivia",
        "IE" => "Ireland",
        "PL" => "Poland",
        "RO" => "Romania",
        "CZ" => "Czech Republic",
        "IS" => "Iceland",
        "GR" => "Greece",
        "HR" => "Croatia",
        "IL" => "Israel",
        "SA" => "Saudi Arabia",
        "AE" => "United Arab Emirates",
        "TW" => "Taiwan",
        "LK" => "Sri Lanka",
        "MN" => "Mongolia",
        "BD" => "Bangladesh",
        "GH" => "Ghana",
        _ => code, // Fall back to the code if no name mapping found
    }.to_string()
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