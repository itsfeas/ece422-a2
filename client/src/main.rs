use std::error::Error; 
use tungstenite::{connect, Message}; 
use x25519_dalek::{EphemeralSecret, PublicKey};
use url::Url; 


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


fn key_exchange(server_addr: &Url) {
    
    let rand_num = rand::thread_rng(); 
    let client_secret = EphemeralSecret::new(rand_num);
    let client_public = PublicKey::from(&client_secret);

    // make call to server for server'publicKey 
    //
    
    let (mut socket, response) = connect(server_addr.clone()).expect("Failed to connect");

    socket.send(Message::Text("new".into())).unwrap();
    let msg = socket.read().expect("Error reading message");
    println!("Received: {}", msg);

    // deffie-hellmamn

}
