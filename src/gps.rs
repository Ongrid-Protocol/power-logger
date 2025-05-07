use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Country {
    pub code: String,    // ISO 3166-1 alpha-2 country code
    pub name: String,    // Full country name
    pub region: String,  // Geographic region
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp: u64,
    pub accuracy: f32,
    pub satellites: u8,
    pub altitude: f64,
    pub country: Option<Country>,  // Country information
}

impl Location {
    pub fn new(latitude: f64, longitude: f64, altitude: f64, accuracy: f32, satellites: u8) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            latitude,
            longitude,
            altitude,
            timestamp,
            accuracy,
            satellites,
            country: Self::detect_country(latitude, longitude),
        }
    }

    pub fn is_valid(&self) -> bool {
        // Basic validation of GPS coordinates
        self.latitude >= -90.0 && self.latitude <= 90.0 &&
        self.longitude >= -180.0 && self.longitude <= 180.0 &&
        self.accuracy > 0.0 && self.accuracy < 100.0 && // Accuracy better than 100 meters
        self.satellites >= 4 && // At least 4 satellites for good accuracy
        self.country.is_some()  // Must have valid country information
    }

    pub fn distance_to(&self, other: &Location) -> f64 {
        // Haversine formula to calculate distance between two points
        let r = 6371000.0; // Earth's radius in meters
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat/2.0).sin().powi(2) +
                lat1.cos() * lat2.cos() * (delta_lon/2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        r * c
    }

    pub fn is_within_radius(&self, other: &Location, radius_meters: f64) -> bool {
        self.distance_to(other) <= radius_meters
    }

    pub fn is_same_country(&self, other: &Location) -> bool {
        match (&self.country, &other.country) {
            (Some(c1), Some(c2)) => c1.code == c2.code,
            _ => false,
        }
    }

    fn detect_country(latitude: f64, longitude: f64) -> Option<Country> {
        // This is a simplified version. In a real implementation, you would:
        // 1. Use a proper geocoding service
        // 2. Cache results
        // 3. Handle edge cases near borders
        
        // Example country boundaries (simplified)
        let countries: HashMap<&str, (f64, f64, f64, f64)> = HashMap::from([
            ("US", (24.396308, -125.000000, 49.384358, -66.934570)), // USA
            ("GB", (49.871159, -8.623555, 60.860699, 1.762915)),    // UK
            ("DE", (47.270111, 5.866315, 55.099161, 15.041896)),    // Germany
            ("FR", (41.333, -5.5591, 51.124, 9.6625)),              // France
            ("IT", (35.2889, 6.6273, 47.0921, 18.7845)),            // Italy
            ("ES", (27.4335, -18.3937, 43.9933, 4.5919)),           // Spain
        ]);

        for (code, (min_lat, min_lon, max_lat, max_lon)) in countries {
            if latitude >= min_lat && latitude <= max_lat &&
               longitude >= min_lon && longitude <= max_lon {
                return Some(Country {
                    code: code.to_string(),
                    name: Self::get_country_name(code),
                    region: Self::get_country_region(code),
                });
            }
        }
        None
    }

    fn get_country_name(code: &str) -> String {
        match code {
            "US" => "United States",
            "GB" => "United Kingdom",
            "DE" => "Germany",
            "FR" => "France",
            "IT" => "Italy",
            "ES" => "Spain",
            _ => "Unknown",
        }.to_string()
    }

    fn get_country_region(code: &str) -> String {
        match code {
            "US" => "North America",
            "GB" | "DE" | "FR" | "IT" | "ES" => "Europe",
            _ => "Unknown",
        }.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_validation() {
        let valid_location = Location::new(40.7128, -74.0060, 0.0, 5.0, 8);
        assert!(valid_location.is_valid());

        let invalid_latitude = Location::new(91.0, -74.0060, 0.0, 5.0, 8);
        assert!(!invalid_latitude.is_valid());

        let invalid_accuracy = Location::new(40.7128, -74.0060, 0.0, 200.0, 8);
        assert!(!invalid_accuracy.is_valid());

        let insufficient_satellites = Location::new(40.7128, -74.0060, 0.0, 5.0, 2);
        assert!(!insufficient_satellites.is_valid());
    }

    #[test]
    fn test_distance_calculation() {
        let location1 = Location::new(40.7128, -74.0060, 0.0, 5.0, 8);
        let location2 = Location::new(40.7128, -74.0060, 0.0, 5.0, 8);
        assert_eq!(location1.distance_to(&location2), 0.0);

        let location3 = Location::new(40.7128, -74.0060, 0.0, 5.0, 8);
        let location4 = Location::new(40.7128, -73.9960, 0.0, 5.0, 8);
        let distance = location3.distance_to(&location4);
        assert!(distance > 0.0 && distance < 1000.0);
    }

    #[test]
    fn test_country_detection() {
        // Test US location
        let us_location = Location::new(40.7128, -74.0060, 0.0, 5.0, 8);
        assert!(us_location.country.is_some());
        assert_eq!(us_location.country.as_ref().unwrap().code, "US");
        assert_eq!(us_location.country.as_ref().unwrap().name, "United States");
        assert_eq!(us_location.country.as_ref().unwrap().region, "North America");

        // Test UK location
        let uk_location = Location::new(51.5074, -0.1278, 0.0, 5.0, 8);
        assert!(uk_location.country.is_some());
        assert_eq!(uk_location.country.as_ref().unwrap().code, "GB");
        assert_eq!(uk_location.country.as_ref().unwrap().name, "United Kingdom");
        assert_eq!(uk_location.country.as_ref().unwrap().region, "Europe");

        // Test invalid location (middle of ocean)
        let invalid_location = Location::new(0.0, 0.0, 0.0, 5.0, 8);
        assert!(invalid_location.country.is_none());
    }

    #[test]
    fn test_same_country_check() {
        let location1 = Location::new(40.7128, -74.0060, 0.0, 5.0, 8); // New York
        let location2 = Location::new(34.0522, -118.2437, 0.0, 5.0, 8); // Los Angeles
        assert!(location1.is_same_country(&location2));

        let location3 = Location::new(51.5074, -0.1278, 0.0, 5.0, 8); // London
        assert!(!location1.is_same_country(&location3));
    }
} 