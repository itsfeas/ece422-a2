use std::io::Error; 
use tungstenite::{connect, Message, WebSocket}; 
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use url::Url; 
use serde::{Serialize, Deserialize};
use futures::Stream;

use model::model::AppMessage;  
// use serde::{serialize, deserialize}; 


enum LoginStatus {
    New(String),
    Attempt(String), 
    Failed(String)
}



/////////////////////////////////
///                           ///
/// FUNCTIONS                 ///
///                           ///
/////////////////////////////////

fn main() -> Result<(), Error> {
    let server_addr = "127.0.0.1:8080";
    
    let url = Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
    let (mut socket, response) = connect(url).expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    loop {

        // obtain input from command line 
        let cmd_input = String::from("new"); 
        
        try_login(cmd_input, &mut socket); 


    }

    Ok(())
}


fn try_login<S>(input_str: String, socket: &mut WebSocket<S>) -> LoginStatus where S: std::io::Read, S: std::io::Write  {
    let app_message = command_parser(input_str).unwrap();  
    println!("DEBUG: {:?}", app_message); 
    
    if app_message.cmd == "new" {
        println!("DEBUG: reached"); 
        let shared_secret = key_exchange(socket); 
        println!("DEBUG: {:?}", Vec::from(shared_secret.as_ref()));  
        // user types username 
        let username = String::from("itsnotfeas"); 

        // encrypt 
        
        // send to socket (username, encrypted username)

        return LoginStatus::New(username); 
    }

    LoginStatus::Failed("".to_string())
    // else
}

fn command_parser(input_str: String) -> Result<AppMessage, String> {
    let mut result = input_str.split_whitespace().map(|simple_str| String::from(simple_str)).collect::<Vec<String>>();  

    let message = match result.pop() {
        Some(cmd_val) => {
            AppMessage {
                cmd: cmd_val, 
                data: result 
            }
        }, 
        None => return Err("Failure".to_string()), 
    }; 
    return Ok(message); 
}


fn key_exchange<S>(socket: &mut WebSocket<S>) -> SharedSecret where S: std::io::Read, S: std::io::Write { 
    
    let rand_num = rand::thread_rng(); 
    let client_secret = EphemeralSecret::new(rand_num);
    let client_public = PublicKey::from(&client_secret);

    // make call to server for server'publicKey 
    //
    
    let app_message = AppMessage {
        cmd: String::from("new"), 
        data: vec![serde_json::to_string(&client_public).unwrap()]
    }; 


    socket.send(Message::Text(serde_json::to_string(&app_message).unwrap())).unwrap();
    println!("Message sent"); 
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
