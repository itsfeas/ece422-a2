use std::{io::Error, str::from_utf8}; 
use tungstenite::{connect, Message, WebSocket}; 
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use url::Url; 
use serde::{Serialize, Deserialize};
use futures::Stream;
use model::{cmd::MapStr, model::{AppMessage, Cmd}};
use rand_core::OsRng;
// use serde::{serialize, deserialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};

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
    
    if app_message.cmd == Cmd::NewConnection {
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

fn encrypt_msg(key: &mut Option<Key<Aes256Gcm>>, msg: &AppMessage) -> String {
    let msq_serial = serde_json::to_string(msg).unwrap();
    let cipher = Aes256Gcm::new(&(key).unwrap());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, msq_serial.as_ref()).unwrap();
    from_utf8(&ciphertext).unwrap().to_string()
}

fn command_parser(input_str: String) -> Result<AppMessage, String> {
    let mut result = input_str.split_whitespace().map(|simple_str| String::from(simple_str)).collect::<Vec<String>>();  

    let message = match result.pop() {
        Some(cmd_val) => {
            AppMessage {
                cmd: Cmd::from_str(cmd_val).expect("command could not be mapped!"), 
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
        cmd: Cmd::NewConnection, 
        data: vec![serde_json::to_string(&client_public).unwrap()]
    }; 


    socket.send(Message::Text(serde_json::to_string(&app_message).unwrap())).unwrap();
    println!("Message sent"); 
    let msg = socket.read().expect("Error reading message");
    println!("Received: {}", msg);

    let server_public_key_msg: AppMessage = serde_json::from_str(msg.to_text().unwrap()).expect("Deserialize failed for server_pub_key_msg!");
    let server_public: PublicKey = serde_json::from_str(&server_public_key_msg.data[0]).expect("Deserialize failed for server_public!");
    // if msg.is_text() || msg.is_binary(){
    // } else {
    //     panic!("Deserialization failed")
    // }

    let client_shared_key = client_secret.diffie_hellman(&server_public); 
    println!("client_shared_key {:?}", client_shared_key.as_bytes());
    
    return client_shared_key; 

    // deffie-hellmamn

}
