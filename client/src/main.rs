use std::error::Error; 
use tungstenite::{connect, Message}; 
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use url::Url; 
use serde::{Serialize, Deserialize}; 

use model::model::AppMessage;  
// use serde::{serialize, deserialize}; 


fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:8080";
    
    let url = Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
    let (mut socket, response) = connect(url).expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    loop {
        socket.send(Message::Text("Hello WebSocket".into())).unwrap();
        let msg = socket.read().expect("Error reading message");
        println!("Received: {}", msg);
    }

    Ok(())
}


fn key_exchange(server_addr: &Url) -> SharedSecret {
    
    let rand_num = rand::thread_rng(); 
    let client_secret = EphemeralSecret::new(rand_num);
    let client_public = PublicKey::from(&client_secret);

    // make call to server for server'publicKey 
    //
    
    let (mut socket, response) = connect(server_addr.clone()).expect("Failed to connect");
    let app_message = AppMessage {
        cmd: String::from("new"), 
        data: vec![String::from("")]
    }; 


    socket.send(Message::Text(serde_json::to_string(&app_message).unwrap())).unwrap();
    let msg = socket.read().expect("Error reading message");
    println!("Received: {}", msg);

    let mut server_public: PublicKey; 
    if msg.is_text() || msg.is_binary(){
        server_public = serde_json::from_str(msg.to_text().unwrap()).expect("Deserialize failed");  
    } else {
        panic!("Deserialization failed")
    }

    let client_shared_key = client_secret.diffie_hellman(&server_public); 
    
    return client_shared_key; 

    // deffie-hellmamn

}
