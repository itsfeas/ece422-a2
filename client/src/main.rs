use std::{io::{self, Error}, ops::Neg, str::from_utf8}; 
use log::Log;
use tungstenite::{connect, Message, WebSocket}; 
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use url::Url; 
use serde::{Serialize, Deserialize};
use futures::Stream;
use model::{cmd::{self, MapStr}, model::{AppMessage, Cmd, Path}};
use rand_core::OsRng;
// use serde::{serialize, deserialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use typenum::U12; 

#[derive(Debug, Clone)]
enum LoginStatus {
    New(),
    Success((String, bool)), 
    Failure()
}



/////////////////////////////////
///                           ///
/// FUNCTIONS                 ///
///                           ///
/////////////////////////////////

fn get_input(std_io: &io::Stdin, buffer: &mut String) {
    std_io.read_line(buffer).expect("failed to readline");
    buffer.pop();
}

fn main() -> Result<(), Error> {

    loop {

        let server_addr = "127.0.0.1:8080";
        
        let url = Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
        let (mut socket, response) = connect(url).expect("Failed to connect");
        println!("WebSocket handshake has been successfully completed");
        
        // Key transfer at the beginning of the session
        let diffie_key = key_exchange(&mut socket); 
        // convert to Aes256Gcm key 
        let aes_key: Key<Aes256Gcm> = diffie_key.to_bytes().into();
        let mut line = String::new();
        let std_io = io::stdin();
        println!("Welcome");
        println!("Login as follows: login <username> <password>");
        println!("Or sign up as a new user: new_user <username> <password>");
        // obtain input from command line 
        get_input(&std_io, &mut line);
        let cmd_input = String::from(line); // placeholder -- user can type username or "new"
        println!("DEBUG: {:?}", cmd_input);

        let app_message = command_parser(cmd_input.clone()).unwrap();  
        println!("DEBUG: {:?}", app_message);

        let mut login_state;
        match app_message.cmd {
            Cmd::Login | Cmd::NewUser => {
                login_state = login_signup(&app_message, &mut socket, &mut aes_key.clone());  
            },
            _ => {
                println!("Please use one of the commands as specified.");
                continue;
            }
        }
        
        
        if let LoginStatus::New() = login_state.clone() {
            println!("signup successful");
            continue;
        };
        if let LoginStatus::Failure() = login_state.clone() {
            println!("failure");
            continue;
        };
        if let LoginStatus::Success(s) = login_state.clone() {
            
            println!("login successful");
            let mut path = Path {
                path: vec![(false, "/".into()), (false, "home".into()), (false, s.0.clone())]
            };

            // integrity check with server 
            

            loop {
                println!("Enter Command");
                let mut line = String::new();
                let std_io = io::stdin();
                get_input(&std_io, &mut line);
                // obtain input from command line 
                let cmd_input = String::from(line); 

                let app_message = command_parser(cmd_input).unwrap();  
                println!("DEBUG: {:?}", app_message); 




                if app_message.cmd == Cmd::NewConnection {
                    // setup_connection
                } else if app_message.cmd == Cmd::Echo { 
                    // AppMessage: echo <current path> <echo message> [">" <path to file to echo to>] 

                } else if app_message.cmd == Cmd::Cd { 
                    // AppMessage: cd <current path> <path to cd to>, since the server searches
                    // from root 
                } else if app_message.cmd == Cmd::Touch {
                    // AppMessage: touch <current path> <new file>, since the server searches
                    // from root 
                }



            }

        }
        else {

        }



    }
    // Ok(())
}

// fn setup_connection<S>(socket: &mut WebSocket<S>) where S: std::io::Read, S: std::io::Write {
//     let shared_secret = key_exchange(socket); 
//     println!("DEBUG: {:?}", Vec::from(shared_secret.as_ref()));  
// }

/*
 * input_str: either the username, or "new" */
fn login_signup<S>(msg: &AppMessage, socket: &mut WebSocket<S>, key: &mut Key<Aes256Gcm>) -> LoginStatus where S: std::io::Read, S: std::io::Write  {

    
    send_encrypt(msg, socket, key);
    println!("Message sent"); 
    let response = socket.read().expect("Error reading message");
    println!("Received: {}", response);
    // println!("DEBUG: reached"); 
    let login_res: AppMessage = serde_json::from_str(response.to_text().unwrap()).expect("Deserialize failed for login/signup response!");
    // let server_public: Cmd = serde_json::from_str(&login_res.cmd).expect("Deserialize failed for server_public!");
    match login_res.cmd {
        Cmd::NewUser => {
            return LoginStatus::Success((String:: from("signup successful"), false));
        },
        Cmd::Login => {
            let is_admin: bool = match login_res.data[1].as_str() {
                "true" => true,
                "false" => false,
                _ => false
            };
            return LoginStatus::Success((login_res.data[0].clone(),is_admin));
        },
        Cmd::Failure => {
            return LoginStatus::Failure();
        },
        _ => {todo!()}

    }
    // user types username 
    // let username = String::from("itsnotfeas"); 

    // encrypt
    
    
    // send to socket (username, encrypted username)

    // return LoginStatus::New(username); 

    // LoginStatus::Failed("".to_string())
    // else
}

fn encrypt_msg(key: &mut Option<Key<Aes256Gcm>>, msg: &AppMessage) -> (String, Nonce<typenum::U12>) {
    let msq_serial = serde_json::to_string(msg).unwrap();
    let cipher = Aes256Gcm::new(&(key).unwrap());
    let nonce: Nonce<typenum::U12> = Aes256Gcm::generate_nonce(&mut OsRng);
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

    let message = match result.get(0) {
        Some(cmd_val) => {
            AppMessage {
                cmd: Cmd::from_str(cmd_val.clone()).expect("command could not be mapped!"), 
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

fn send_encrypt<S>(msg: &AppMessage, socket: &mut WebSocket<S>, key: &Key<Aes256Gcm>) -> Result<(), String> where S: std::io::Read, S: std::io::Write{
   
    let (encrypted_msg, nonce) = encrypt_msg(&mut Some(key.clone()), msg);

    socket.send(Message::Text(
                serde_json::to_string::<(std::string::String, [u8; 12])>(&(encrypted_msg, nonce.into())).expect("serialization failed")
            )).expect("Send failed"); 
    Ok(())
}

fn recv_decrypt<S>(socket: &mut WebSocket<S>, key: &mut Key<Aes256Gcm>) -> Result<AppMessage, String> where S: std::io::Read, S: std::io::Write {
    
    let message = socket.read().expect("Error reading message"); 
    let (str_message_enc, nonce_array): (String, [u8; 12]) = serde_json::from_str(message.to_text().unwrap()).expect("deserialization of nonce message failed"); 
    let nonce: aes_gcm::Nonce<U12> = nonce_array.into();
    let app_msg = decrypt_msg(&mut Some(key.clone()), nonce, str_message_enc);
    return Ok(app_msg); 
}


fn cd<S>(app_message: AppMessage, 
         socket: &mut WebSocket<S>, 
         encryption_key: &mut Key<Aes256Gcm>, 
         current_path: &mut Path) -> Result<(), String>  where S: std::io::Read, S: std::io::Write { 

    let target_dir: String = app_message.data[0].clone(); 
    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 


    let rec_app_message = recv_decrypt(socket, encryption_key).expect("Recv decrypt failed"); 
    if rec_app_message.cmd == Cmd::Cd {
        process_local_cd_path(target_dir, current_path).expect("Path construction error")
    } else {
        println!("Directory does not exist"); 
    }
    return Ok(()); 

}


fn ls<S>(app_message: AppMessage, 
        socket: &mut WebSocket<S>, 
        encryption_key: &mut Key<Aes256Gcm>) -> Result<(), String> where S: std::io::Read, S: std::io::Write {

    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 

    let recv_app_message = recv_decrypt(socket, encryption_key).expect("Recv decrypt failed"); 
    if recv_app_message.cmd == Cmd::Ls {
        recv_app_message.data.iter().for_each(|x| {
            println!("{}", x); 
        }); 
        return Ok(());
    }  
    return Err(String::from("Something unexpected happened when trying to Ls")); 

}



fn touch<S>(app_message: AppMessage, 
        socket: &mut WebSocket<S>, 
        encryption_key: &mut Key<Aes256Gcm>) -> Result<(), String> where S: std::io::Read, S: std::io::Write {

    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 

    let recv_app_message = recv_decrypt(socket, encryption_key).expect("Recv decrypt failed"); 
    if recv_app_message.cmd == Cmd::Touch {
        return Ok(());
    } else if recv_app_message.cmd == Cmd::Failure {
        println!("{}", recv_app_message.data[0]);
    } 
    return Ok(()); 
}


fn pwd(app_message: AppMessage, 
       current_path: &Path) -> Result<(), Error> {
    let mut str_path = current_path.path.iter().map(|x| {
        if x.clone().0 {
            panic!("encrypted message received")
        }
        x.1.clone()
    }).collect::<Vec<String>>().join("/"); 
    
    str_path.insert_str(0, "/"); 
    println!("{}", str_path); 
    Ok(())

}


fn echo<S>(app_message: AppMessage, 
        socket: &mut WebSocket<S>, 
        encryption_key: &mut Key<Aes256Gcm>) -> Result<(), String> where S: std::io::Read, S: std::io::Write {
    if app_message.data.len() == 2 {
        println!("{}", &app_message.data[1]);
        return Ok(()); 
    }
    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 

    let recv_app_message = recv_decrypt(socket, encryption_key).expect("Recv decrypt failed"); 
    if recv_app_message.cmd == Cmd::Touch {
        return Ok(());
    } else if recv_app_message.cmd == Cmd::Failure {
        println!("{}", recv_app_message.data[0]);
    } 
    return Ok(()); 
}

/*
 * Inputs: 
 *      filenames: Human readable filenames 
 * Returns
 *      vector of encrypted filenames 
 * */
fn get_encrypted_filenames<S>(filenames: Vec<String>, socket: &mut WebSocket<S>, key: &mut Key<Aes256Gcm>) -> Result<Vec<String>, String> where S: std::io::Read, S: std::io::Write {
    let msg = AppMessage {
        cmd:Cmd::GetEncryptedFile, 
        data: filenames
    };
    send_encrypt(&msg, socket, key).expect("Send get encrypted filenames failed"); 
    let recv_msg= recv_decrypt(socket, key).expect("Recv get encrypted filenames failed"); 
    if recv_msg.cmd == Cmd::GetEncryptedFile {
        return Ok(recv_msg.data); 
    } 
    return Err(String::from("Server did not send GetEncryptedFile.")); 
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



