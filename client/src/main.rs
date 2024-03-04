use std::error::Error; 
use tungstenite::{connect, Message}; 


fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:8080";
    
    let url = url::Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
    let (mut socket, response) = connect(url).expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    loop {
        socket.send(Message::Text("Hello WebSocket".into())).unwrap();
        let msg = socket.read().expect("Error reading message");
        println!("Received: {}", msg);
    }

    Ok(())
}
