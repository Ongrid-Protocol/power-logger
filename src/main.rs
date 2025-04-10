// power-logger/src/main.rs
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::net::TcpListener;
use std::io::{Read, Write};
use std::path::Path;
use rand::Rng;
use power_logger::gps::Location;
use power_logger::config::Config;
use power_logger::sensors::SensorReadings;
use power_logger::power::PowerReadings;
use power_logger::crypto::{Crypto, EncryptedData, CryptoError};

#[derive(Serialize, Deserialize, Debug)]
struct PowerData {
    timestamp: u64,
    sensor_readings: SensorReadings,
    power_readings: PowerReadings,
    device_id: String,
    location: Location,
}

impl PowerData {
    fn new(device_id: &str, config: &Config, crypto: &Crypto) -> Result<EncryptedData, CryptoError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get device configuration
        let device_config = config.get_device(device_id)
            .expect(&format!("Device {} not found in configuration", device_id));
        
        // Get location from configuration
        let location = config.get_device_location(device_id)
            .expect(&format!("Location not found for device {}", device_id));

        // Generate sensor and power readings
        let sensor_readings = SensorReadings::new(device_config);
        let power_readings = PowerReadings::new(device_config);

        // Create the data structure
        let data = Self {
            timestamp,
            sensor_readings,
            power_readings,
            device_id: device_id.to_string(),
            location,
        };

        // Encrypt the data
        crypto.encrypt(&data)
    }

    pub fn is_location_valid(&self) -> bool {
        self.location.is_valid()
    }

    pub fn is_within_radius(&self, other_location: &Location, radius_meters: f64) -> bool {
        self.location.is_within_radius(other_location, radius_meters)
    }

    pub fn is_same_country(&self, other: &PowerData) -> bool {
        self.location.is_same_country(&other.location)
    }
}

fn handle_client(mut stream: std::net::TcpStream, config: &Config, crypto: &Crypto) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(size) => {
            let request = String::from_utf8_lossy(&buffer[..size]);
            if request.trim() == "GET_DATA" {
                let device_id = "RASPBERRY_PI_1"; // This should come from the request
                match PowerData::new(device_id, config, crypto) {
                    Ok(encrypted_data) => {
                        if let Ok(response) = serde_json::to_string(&encrypted_data) {
                            if let Err(e) = stream.write(response.as_bytes()) {
                                println!("Error writing to client: {}", e);
                            }
                            if let Err(e) = stream.flush() {
                                println!("Error flushing stream: {}", e);
                            }
                        } else {
                            println!("Error serializing encrypted data");
                        }
                    }
                    Err(e) => println!("Error encrypting data: {}", e),
                }
            }
        }
        Err(e) => println!("Error reading from client: {}", e),
    }
}

fn main() {
    // Load configuration
    let config_path = Path::new("config/devices.yaml");
    let config = Config::load(config_path).expect("Failed to load configuration");

    // Initialize crypto with a secure key
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    let crypto = Crypto::new(key);

    // Start server
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    println!("Power logger simulator running on 127.0.0.1:7878");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = config.clone();
                let crypto = crypto.clone();
                thread::spawn(move || {
                    handle_client(stream, &config, &crypto);
                });
            }
            Err(e) => {
                println!("Error accepting connection: {}", e);
            }
        }
    }
}