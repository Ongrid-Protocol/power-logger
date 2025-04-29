-- Create database if not exists
CREATE DATABASE power_logger;

-- Connect to the database
\c power_logger;

-- Create extension for UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum for light intensity
CREATE TYPE light_intensity AS ENUM ('Low', 'Medium', 'High');

-- Create tables
CREATE TABLE IF NOT EXISTS power_data (
    id SERIAL PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    device_id VARCHAR(50) NOT NULL,
    power_produced FLOAT,
    battery_storage FLOAT,
    power_consumed FLOAT,
    device_consumption FLOAT,
    power_produced_kwh FLOAT,
    battery_storage_kwh FLOAT,
    power_consumed_kwh FLOAT,
    device_consumption_kwh FLOAT,
    ac_voltage FLOAT,
    ac_current FLOAT,
    ac_power FLOAT,
    ac_energy FLOAT,
    ac_frequency FLOAT,
    ac_power_factor FLOAT,
    verification_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sensor_readings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(50) REFERENCES devices(device_id),
    timestamp BIGINT,
    temperature1 DECIMAL(10, 6),
    temperature2 DECIMAL(10, 6),
    ldr_value INTEGER,
    ldr_voltage DECIMAL(10, 6),
    ldr_intensity light_intensity,
    current_ma DECIMAL(10, 4)[],
    voltage_mv DECIMAL(10, 2)[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(50) REFERENCES devices(device_id),
    latitude DECIMAL(10, 6),
    longitude DECIMAL(10, 6),
    altitude DECIMAL(10, 2),
    accuracy DECIMAL(5, 2),
    satellites INTEGER,
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    timestamp BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS verification_logs (
    id SERIAL PRIMARY KEY,
    power_data_id INTEGER REFERENCES power_data(id),
    node_id VARCHAR(100) NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create table for device information
CREATE TABLE devices (
    device_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create table for power readings
CREATE TABLE power_readings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(50) REFERENCES devices(device_id),
    timestamp BIGINT,
    power_produced DECIMAL(10, 6),
    battery_storage DECIMAL(10, 6),
    power_consumed DECIMAL(10, 6),
    device_consumption DECIMAL(10, 6),
    power_produced_kwh DECIMAL(10, 8),
    battery_storage_kwh DECIMAL(10, 8),
    power_consumed_kwh DECIMAL(10, 8),
    device_consumption_kwh DECIMAL(10, 8),
    ac_voltage DECIMAL(10, 6),
    ac_current DECIMAL(10, 6),
    ac_power DECIMAL(10, 6),
    ac_energy DECIMAL(10, 6),
    ac_frequency DECIMAL(10, 6),
    ac_power_factor DECIMAL(10, 6),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create table for verification records
CREATE TABLE verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_hash VARCHAR(64),
    device_id VARCHAR(50) REFERENCES devices(device_id),
    timestamp BIGINT,
    verified_by TEXT[],
    verification_count INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_power_data_timestamp ON power_data(timestamp);
CREATE INDEX IF NOT EXISTS idx_power_data_device_id ON power_data(device_id);
CREATE INDEX idx_sensor_readings_device_id ON sensor_readings(device_id);
CREATE INDEX idx_sensor_readings_timestamp ON sensor_readings(timestamp);
CREATE INDEX idx_power_readings_device_id ON power_readings(device_id);
CREATE INDEX idx_power_readings_timestamp ON power_readings(timestamp);
CREATE INDEX idx_locations_device_id ON locations(device_id);
CREATE INDEX idx_verifications_message_hash ON verifications(message_hash);
CREATE INDEX IF NOT EXISTS idx_verification_logs_node_id ON verification_logs(node_id); 