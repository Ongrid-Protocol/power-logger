use std::net::TcpStream;
use std::io::{Read, Write};

fn main() {
    // Connect to the power logger server
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            println!("Successfully connected to power logger server at 127.0.0.1:7878");
            
            // Send GET_DATA request
            let request = "GET_DATA";
            match stream.write(request.as_bytes()) {
                Ok(_) => {
                    println!("Sent request: {}", request);
                    
                    // Read the response
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(size) => {
                            let response = String::from_utf8_lossy(&buffer[..size]);
                            println!("\nReceived response from server:");
                            println!("{}", response);
                        }
                        Err(e) => println!("Failed to read response: {}", e),
                    }
                }
                Err(e) => println!("Failed to send request: {}", e),
            }
        }
        Err(e) => println!("Failed to connect: {}", e),
    }
} 