-- Create database if not exists
CREATE DATABASE power_logger;

-- Connect to the database
\c power_logger;

-- Create extension for UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum for light intensity
CREATE TYPE light_intensity AS ENUM ('Low', 'Medium', 'High');

-- Create enum types
CREATE TYPE device_type AS ENUM ('solar_controller');
CREATE TYPE phase_type AS ENUM ('single', 'three');

-- Create tables
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    device_type device_type NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    max_wattage INTEGER NOT NULL,
    voltage_range VARCHAR(20) NOT NULL,
    frequency_range VARCHAR(10) NOT NULL,
    battery_capacity VARCHAR(20) NOT NULL,
    phase_type phase_type NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(20) REFERENCES devices(device_id),
    latitude DECIMAL(10, 6),
    longitude DECIMAL(10, 6),
    altitude DECIMAL(10, 2),
    accuracy DECIMAL(5, 2),
    satellites INTEGER,
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    timestamp BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    message_hash VARCHAR(64) UNIQUE NOT NULL,
    content TEXT NOT NULL,
    originator_id VARCHAR(100) NOT NULL,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS message_signers (
    id SERIAL PRIMARY KEY,
    message_hash VARCHAR(64) REFERENCES messages(message_hash),
    signer_id VARCHAR(100) NOT NULL,
    signed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(message_hash, signer_id)
);

CREATE TABLE IF NOT EXISTS verified_data (
    id SERIAL PRIMARY KEY,
    message_hash VARCHAR(64) REFERENCES messages(message_hash),
    device_id VARCHAR(20) REFERENCES devices(device_id),
    timestamp BIGINT NOT NULL,
    temperature DECIMAL(5,2) NOT NULL,
    light INTEGER NOT NULL,
    current INTEGER NOT NULL,
    voltage INTEGER NOT NULL,
    power_generated DECIMAL(10,2),
    power_consumed DECIMAL(10,2),
    battery_level DECIMAL(5,2),
    verification_count INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_verified_data_device_id ON verified_data(device_id);
CREATE INDEX IF NOT EXISTS idx_verified_data_timestamp ON verified_data(timestamp);
CREATE INDEX IF NOT EXISTS idx_verified_data_power_generated ON verified_data(power_generated);
CREATE INDEX IF NOT EXISTS idx_verified_data_power_consumed ON verified_data(power_consumed);
CREATE INDEX IF NOT EXISTS idx_locations_country_code ON locations(country_code);
CREATE INDEX IF NOT EXISTS idx_messages_hash ON messages(message_hash);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_message_signers_hash ON message_signers(message_hash);
CREATE INDEX IF NOT EXISTS idx_message_signers_signer ON message_signers(signer_id);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;
CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_locations_updated_at ON locations;
CREATE TRIGGER update_locations_updated_at
    BEFORE UPDATE ON locations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create view for power generation statistics
CREATE OR REPLACE VIEW power_generation_stats AS
SELECT 
    d.device_id,
    d.name as device_name,
    l.country_code,
    l.country_name,
    l.region,
    DATE_TRUNC('day', to_timestamp(vd.timestamp)) as date,
    AVG(vd.power_generated) as avg_power_generated,
    MAX(vd.power_generated) as max_power_generated,
    MIN(vd.power_generated) as min_power_generated,
    SUM(vd.power_generated) as total_power_generated,
    COUNT(DISTINCT ms.signer_id) as unique_signers
FROM verified_data vd
JOIN devices d ON vd.device_id = d.device_id
JOIN locations l ON d.device_id = l.device_id
JOIN messages m ON vd.message_hash = m.message_hash
JOIN message_signers ms ON m.message_hash = ms.message_hash
GROUP BY d.device_id, d.name, l.country_code, l.country_name, l.region, date
ORDER BY date DESC;

-- Create view for power consumption statistics
CREATE OR REPLACE VIEW power_consumption_stats AS
SELECT 
    d.device_id,
    d.name as device_name,
    l.country_code,
    l.country_name,
    l.region,
    DATE_TRUNC('day', to_timestamp(vd.timestamp)) as date,
    AVG(vd.power_consumed) as avg_power_consumed,
    MAX(vd.power_consumed) as max_power_consumed,
    MIN(vd.power_consumed) as min_power_consumed,
    SUM(vd.power_consumed) as total_power_consumed,
    COUNT(DISTINCT ms.signer_id) as unique_signers
FROM verified_data vd
JOIN devices d ON vd.device_id = d.device_id
JOIN locations l ON d.device_id = l.device_id
JOIN messages m ON vd.message_hash = m.message_hash
JOIN message_signers ms ON m.message_hash = ms.message_hash
GROUP BY d.device_id, d.name, l.country_code, l.country_name, l.region, date
ORDER BY date DESC;

-- Create view for message verification status
CREATE OR REPLACE VIEW message_verification_status AS
SELECT 
    m.message_hash,
    m.originator_id,
    m.timestamp,
    COUNT(DISTINCT ms.signer_id) as signer_count,
    array_agg(DISTINCT ms.signer_id) as signers,
    vd.verification_count,
    vd.device_id,
    vd.power_generated,
    vd.power_consumed
FROM messages m
LEFT JOIN message_signers ms ON m.message_hash = ms.message_hash
LEFT JOIN verified_data vd ON m.message_hash = vd.message_hash
GROUP BY m.message_hash, m.originator_id, m.timestamp, vd.verification_count, vd.device_id, vd.power_generated, vd.power_consumed
ORDER BY m.timestamp DESC; 