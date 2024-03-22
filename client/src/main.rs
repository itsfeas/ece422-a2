use std::{io::Error, str::from_utf8}; 
use tungstenite::{connect, Message, WebSocket}; 
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use url::Url; 
use serde::{Serialize, Deserialize};
use futures::Stream;
use model::{cmd::MapStr, model::{AppMessage, Cmd, Path}};
use rand_core::OsRng;
// use serde::{serialize, deserialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use typenum::U12; 

#[derive(Debug, Clone)]
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

    loop {

        let server_addr = "127.0.0.1:8080";
        
        let url = Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
        let (mut socket, response) = connect(url).expect("Failed to connect");
        println!("WebSocket handshake has been successfully completed");
        
        // Key transfer at the beginning of the session
        let diffie_key = key_exchange(&mut socket); 
        // convert to Aes256Gcm key 
        let aes_key = Aes256Gcm::new((&diffie_key.to_bytes()).into());


        // obtain input from command line 
        let cmd_input = String::from("new"); // placeholder -- user can type username or "new"

        let app_message = command_parser(cmd_input.clone()).unwrap();  
        println!("DEBUG: {:?}", app_message); 
        
        let login_state = try_login(cmd_input, &mut socket);  
        if let LoginStatus::New(s) = login_state.clone() {
            // create new user
        };  
        if let LoginStatus::Attempt(s) = login_state.clone() {
            
            
            let mut path = Path {
                path: vec![(false, "/".into()), (false, "home".into()), (false, s.clone())]
            };

            loop {

                // obtain input from command line 
                let cmd_input = String::from("new"); 

                let app_message = command_parser(cmd_input).unwrap();  
                println!("DEBUG: {:?}", app_message); 




                if app_message.cmd == Cmd::NewConnection {
                    // setup_connection
                } else if app_message.cmd == Cmd::Echo {

                } else if app_message.cmd == Cmd::Cd {
                    
                }



            }

        }
        else {

        }



    }
    Ok(())
}

// fn setup_connection<S>(socket: &mut WebSocket<S>) where S: std::io::Read, S: std::io::Write {
//     let shared_secret = key_exchange(socket); 
//     println!("DEBUG: {:?}", Vec::from(shared_secret.as_ref()));  
// }

/*
 * input_str: either the username, or "new" */
fn try_login<S>(input_str: String, socket: &mut WebSocket<S>) -> LoginStatus where S: std::io::Read, S: std::io::Write  {

    
    
        // println!("DEBUG: reached"); 
        
        // user types username 
        let username = String::from("itsnotfeas"); 

        // encrypt
        
        
        // send to socket (username, encrypted username)

        return LoginStatus::New(username); 

    // LoginStatus::Failed("".to_string())
    // else
}

fn encrypt_msg(key: &mut Option<Key<Aes256Gcm>>, msg: &AppMessage) -> (String, Nonce<typenum::U12>) {
    let msq_serial = serde_json::to_string(msg).unwrap();
    let cipher = Aes256Gcm::new(&(key).unwrap());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, msq_serial.as_ref()).unwrap();
    return (from_utf8(&ciphertext).unwrap().to_string(), nonce); 
}

fn decrypt_msg(key: &mut Option<Key<Aes256Gcm>>, nonce: Nonce<typenum::U12>, string_msg: String) -> AppMessage {
    let cipher = Aes256Gcm::new(&(key).unwrap());
    let ciphertext = cipher.decrypt(&nonce, string_msg.as_bytes()).expect("Decryption failed");

    let rec_app_message:AppMessage = serde_json::from_str(
            String::from_utf8(ciphertext).unwrap().as_str()
        ).expect("Invalid deserializeation"); 
    return rec_app_message; 
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

fn send_encrypt<S>(msg: &AppMessage, socket: &mut WebSocket<S>, key: &mut Key<Aes256Gcm>) -> Result<Nonce<typenum::U12>, String> where S: std::io::Read, S: std::io::Write{
   
    let (encrypted_msg, nonce) = encrypt_msg(&mut Some(key.clone()), msg);

    socket.send(Message::Text(
                encrypted_msg
            )).expect("Send failed"); 
    Ok(nonce)
}

fn recv_decrypt<S>(socket: &mut WebSocket<S>, key: &mut Key<Aes256Gcm>, nonce: Nonce<typenum::U12>) -> Result<AppMessage, String> where S: std::io::Read, S: std::io::Write {
    
    let message = socket.read().expect("Error reading message"); 
    let str_message_enc: String = message.to_text().unwrap().to_string(); 
    let app_msg = decrypt_msg(&mut Some(key.clone()), nonce, str_message_enc);
    return Ok(app_msg); 
}


fn cd<S>(app_message: AppMessage, 
         socket: &mut WebSocket<S>, 
         encryption_key: &mut Key<Aes256Gcm>, 
         current_path: &mut Path)  where S: std::io::Read, S: std::io::Write { 

    let target_dir: String = app_message.data[0].clone(); 
    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 


    let rec_app_message = recv_decrypt(socket, encryption_key, nonce).expect("Recv decrypt failed"); 
    if rec_app_message.cmd == Cmd::Cd {
        process_local_cd_path(target_dir, current_path).expect("Path construction error")
    } else {
        println!("Directory does not exist"); 
    }

}
 
/*
 * cmd_arg: argument of the cd command. For example: if command is cd /home/user/f1, 
 *      then cmd_arg = "/home/user/f1"
 * */
fn process_local_cd_path(cmd_arg: String, current_path: &mut Path) -> Result<(), String> {
    
    // if we do cd /xxxx, we are specifying an absolute path, therefore clear the path vector
    if cmd_arg.clone().as_str().starts_with("/") {
        current_path.path = vec![(false, String::from("/"))]; 
    } 
    cmd_arg.split("/").for_each(|x| {
        // if an element is "..", go back until there is only ["/"] in the vector
        if x == ".." && current_path.path.len() > 1  {
            current_path.path.pop(); 
        // otherwise, we append it to the end
        } else if !x.is_empty() {
            current_path.path.push((false, String::from(x)))
        }
    }); 

    Ok(())
}


fn touch(filename: String, key: &Key<Aes256Gcm>) -> Result<(), String >{


    Ok(())
}

fn echo(filename: String, file_contents: Vec<String>) {
    
}
