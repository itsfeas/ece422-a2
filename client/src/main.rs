use std::fs::create_dir_all;
use std::io; 
use std::{io::Error, str::from_utf8, fs::File, fs::create_dir,  io::stdout, ops::Neg, io::Read, io::Write}; 
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
    New((String, bool)),
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
    
    let server_addr = "127.0.0.1:8080";
        
    let url = Url::parse("ws://127.0.0.1:8080").expect("Failed to unwrap addr"); 
    let (mut socket, response) = connect(url).expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");
    
    // Key transfer at the beginning of the session
    let diffie_key = key_exchange(&mut socket); 
    // convert to Aes256Gcm key 
    let mut aes_key: Key<Aes256Gcm> = diffie_key.to_bytes().into();
    loop {
        let mut line = String::new();
        let std_io = io::stdin();
        println!("Welcome");
        println!("Login as follows: login <username> <password>");
        println!("Or sign up as a new user: new_user <username> <password>");
        // obtain input from command line 
        get_input(&std_io, &mut line);
        let cmd_input = String::from(line.clone()); // placeholder -- user can type username or "new"
        println!("DEBUG: {:?}", cmd_input);

        let mut app_message = command_parser(cmd_input.clone()).unwrap();  
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
        
        
        if let LoginStatus::New(s) = login_state.clone() {
            println!("signup successful");
            let mut path = Path {
                path: vec![(false, "/".into()), (false, "home".into())]
            };

            app_message = AppMessage {cmd: Cmd::Mkdir, data: vec![path.to_string(), s.0.clone()]};
            mkdir(app_message, &mut socket, &mut aes_key,  &path);
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
                print!("{}>>",path);
                stdout().flush();
                // println!("Enter Command");
                let mut line = String::new();
                // let std_io = io::stdin();
                get_input(&std_io, &mut line);
                if (line.is_empty()) {
                    continue;
                }
                // obtain input from command line 
                let cmd_input = String::from(line); 

                app_message = command_parser(cmd_input).unwrap(); 
                
                println!("DEBUG: {:?}", app_message);
                match app_message.cmd {
                    Cmd::Cd => {
                        preprocess_app_message(&mut app_message, &path);
                        cd(app_message, &mut socket, &mut aes_key, &mut path);
                    }
                    Cmd::NewConnection => {},
                    Cmd::Echo => {},
                    Cmd::Touch => {
                        preprocess_app_message(&mut app_message, &path);
                        touch(app_message, &mut socket, &mut aes_key,  &path);
                    },
                    Cmd::Mkdir => {
                        preprocess_app_message(&mut app_message, &path);
                        mkdir(app_message, &mut socket, &mut aes_key,  &path);
                    },
                    Cmd::Ls => {
                        ls(&mut socket, &mut aes_key, &path);
                    },
                    Cmd::Pwd => {},
                    Cmd::Mv => {},
                    Cmd::Cat => {
                        preprocess_app_message(&mut app_message, &path);
                        cat(&mut app_message, &mut socket, &mut aes_key,  &path);
                    },
                    Cmd::Chmod => {},
                    Cmd::CreateGroup => {},
                    
                    _ => {},
                };
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
    // let response = socket.read().expect("Error reading message");
    let login_res = recv_decrypt(socket, key).unwrap();
    // println!("Received: {}", response);
    // println!("DEBUG: reached"); 
    // let login_res: AppMessage = serde_json::from_str(response.to_text().unwrap()).expect("Deserialize failed for login/signup response!");
    // let server_public: Cmd = serde_json::from_str(&login_res.cmd).expect("Deserialize failed for server_public!");
    match login_res.cmd {
        Cmd::NewUser => {
            return LoginStatus::New((login_res.data[0].clone(), false));
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
    return (hex::encode(&ciphertext), nonce); 
}

fn decrypt_msg(key: &mut Option<Key<Aes256Gcm>>, nonce: Nonce<typenum::U12>, string_msg: String) -> AppMessage {
    let cipher = Aes256Gcm::new(&(key).unwrap());
    let from_str: Vec<u8> = hex::decode(&string_msg).unwrap();
    let ciphertext = cipher.decrypt(&nonce, from_str.as_ref()).unwrap();
    println!("msg_recv {}", String::from_utf8(ciphertext.clone()).unwrap().as_str());
    let rec_app_message:AppMessage = serde_json::from_str(
            String::from_utf8(ciphertext).unwrap().as_str()
        ).expect("Invalid deserializeation"); 
    return rec_app_message; 
}

fn command_parser(input_str: String) -> Result<AppMessage, String> {
    let mut result = input_str.split_whitespace().map(|simple_str| String::from(simple_str)).collect::<Vec<String>>();  
    let args = result.split_off(1);
    let message = match result.get(0) {
        Some(cmd_val) => {
            AppMessage {
                cmd: Cmd::from_str(cmd_val.clone()).expect("command could not be mapped!"), 
                data: args
            }
        }, 
        None => return Err("Failure".to_string()), 
    }; 
    return Ok(message); 
}

/*  DEPRECATED
 * */
fn extend_directory(fname: &String) -> String {

    let relative_path = vec!["..", "FILESYSTEM", fname.as_str()].join("/"); 
    return relative_path
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

    let target_dir: String = app_message.data[1].clone(); 
    if target_dir.eq("..") {
        current_path.path.pop(); 
        return Ok(());
    }
    let nonce = send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 

    let rec_app_message = recv_decrypt(socket, encryption_key).expect("Recv decrypt failed"); 
    if rec_app_message.cmd == Cmd::Cd {
        let enc_path = convert_path_to_enc(&target_dir, current_path, socket, encryption_key); 
        if enc_path.path.len() == 0 { // cd to root and home level
            
        } else {
            // for cd, do nothing 
        }
        
        process_local_cd_path(target_dir, current_path).expect("Path construction error");
    } else {
        println!("Directory does not exist"); 
    }
    return Ok(()); 

}

fn mkdir<S>(msg: AppMessage, 
         socket: &mut WebSocket<S>, 
         encryption_key: &mut Key<Aes256Gcm>, 
         current_path: &Path) -> Result<(), String>  where S: std::io::Read, S: std::io::Write {
    let target_path = msg.data[1].clone();  
    send_encrypt(&msg, socket, encryption_key).unwrap(); 
    let recv_msg = recv_decrypt(socket, encryption_key).unwrap(); 
    if recv_msg.cmd == Cmd::Mkdir {
        // let enc_filename = get_encrypted_filenames(vec![target_path.clone()], socket, encryption_key).unwrap()[0].clone(); 
        let enc_filename = recv_msg.data[0].clone(); 
        let mut enc_path = convert_path_to_enc(&target_path, current_path, socket, encryption_key); 
        if enc_path.path.len() == 0 { // cd to root and home level
            println!("{}", "Cannot mkdir on this level.") 
        } else {
            // for cd, do nothing
            //
            let path = enc_path.path.iter().map(|x| {
                    if !x.0 {
                        panic!("Path must be encrypted"); 
                    }
                    x.1.clone()
                }).collect::<Vec<String>>().join("/");
            println!("attempt to create local dir path {}", path.clone());
            create_dir_all(path).unwrap(); 
            
        }
    }

    Ok(())
} 



fn ls<S>(socket: &mut WebSocket<S>, 
        encryption_key: &mut Key<Aes256Gcm>,
        current_path: &Path
    ) -> Result<(), String> where S: std::io::Read, S: std::io::Write {
    let app_message = AppMessage {
        cmd: Cmd::Ls,
        data: vec![current_path.to_string()]
    };
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
        encryption_key: &mut Key<Aes256Gcm>, 
        current_path: &Path) -> Result<(), String> where S: std::io::Read, S: std::io::Write {
    let target_dir = &app_message.data[1].clone(); 
    send_encrypt(&app_message, socket, encryption_key).unwrap(); 

    let recv_app_message = recv_decrypt(socket, encryption_key).unwrap(); 
    if recv_app_message.cmd == Cmd::Touch {
        let path_enc = convert_path_to_enc(&target_dir, current_path, socket, encryption_key); 
        if path_enc.path.len() > 0 {
            File::create(path_enc.path.iter().map(|x| {
                if !x.0 {
                    panic!("Path needs to be encrypted"); 
                }
                x.1.clone()
            }).collect::<Vec<String>>().join("/")).unwrap(); 
        } else  { // else if current path is in root or home 
            println!("cannot make file here"); 
        }

        return Ok(());
    } else if recv_app_message.cmd == Cmd::Failure {
        println!("{}", recv_app_message.data[0]);
    } 
    return Ok(()); 
}


fn cat<S>(msg: &mut AppMessage,
       socket: &mut WebSocket<S>, 
       encryption_key: &mut Key<Aes256Gcm>,
       current_path: &Path
    ) -> Result<(), String> where S:std::io::Read, S:std::io::Write { 
    let target_file = msg.data[1].clone();
    let path_enc = convert_path_to_enc(&target_file, current_path, socket, encryption_key);
    let mut path_enc_string = path_enc.to_string();
    path_enc_string.remove(0);
    println!("path_enc_string, {}", path_enc_string);
    let file_data = match std::fs::read_to_string(path_enc_string) {
        Ok(d) => d,
        Err(e) => "".to_string(), // bad error handling 
    };
    msg.data.append(&mut vec![file_data]);
    send_encrypt(&msg, socket, encryption_key).unwrap(); 
    let unencrypted_data = recv_decrypt(socket, encryption_key).unwrap().data[0].clone();
    println!("{}", unencrypted_data);
    Ok(())
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
    send_encrypt(&app_message, socket, encryption_key).expect("Send Encrypt failed"); 

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
fn get_encrypted_filenames<S>(filename: &String, 
                              current_path: &Path, 
                              socket: &mut WebSocket<S>, 
                              key: &mut Key<Aes256Gcm>) -> Result<Vec<String>, String> where S: std::io::Read, S: std::io::Write {
    let mut cur_path = current_path.path.iter().map(|x| {
        if x.0 {
            panic!("Path names are not supposed to be encrypted"); 
        }
        x.1.clone()
    }).filter(|x| x != "/").collect::<Vec<String>>().join("/"); 
    cur_path.insert_str(0, "/"); 

    let msg = AppMessage {
        cmd:Cmd::GetEncryptedFile, 
        data: vec![cur_path, (*filename).clone()] 
    };
    send_encrypt(&msg, socket, key).expect("Send get encrypted filenames failed"); 
    let recv_msg= recv_decrypt(socket, key).expect("Recv get encrypted filenames failed"); 
    if recv_msg.cmd == Cmd::GetEncryptedFile {
        return Ok(recv_msg.data); 
    } 
    return Err(String::from("Server did not send GetEncryptedFile.")); 
}








///////////////////////////////////////
///     PRE AND POST PROCESSING     ///
///////////////////////////////////////



/*
 *  cmd_arg: argument of the cd command. For example: if command is cd /home/user/f1, 
 *      then cmd_arg = "/home/user/f1"
 *
 *  Usage:
 *      after Cd command confirmed to be successful, update the path 
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
        } else if x == "." {
            // do nothing 

        // otherwise, we append it to the end
        } else if !x.is_empty() {
            current_path.path.push((false, String::from(x)))
        }
    }); 

    Ok(())
}


/*
 *  preprocesses app message to insert current path. 
 *  Current path (in app message, as opposed to the argument current_path) 
 *  will be replaced with the filename argument if filename is an absolute path
 * */

fn preprocess_app_message(app_msg: &mut AppMessage, current_path: &Path) -> Result<(), String> {
    
    // assumes that current path has not been updated
    let mut current_path_str: String;  
    let mut filename = app_msg.data[0].clone(); 

    // if root path specified, replace current path string with filename
    if filename.starts_with("/") {
        let mut current_path_vec = filename.split("/").map(|x| String::from(x)).collect::<Vec<String>>(); 
        if let Some(s) = current_path_vec.pop() {
            filename = s; 
            current_path_str = current_path_vec.join("/"); 
            current_path_str.insert_str(0, "/"); 
        } else {
            filename = String::from("/"); 
            current_path_str = String::from("/"); 
        }
    // else, use current directory
    } else  {
        current_path_str = current_path.path.iter().map(|x| x.1.clone()).collect::<Vec<String>>().join("/");
        current_path_str.remove(0); 
    }
    
    app_msg.data[0] = filename; 
    app_msg.data.insert(0, current_path_str); 
    
    Ok(())

}

/*  ONLY FOR CLIENT SIDE USE
 *  final encrypted path will include the filename
 *  
 * */
fn convert_path_to_enc<S>(filename: &String, 
                          current_path: &Path, 
                          socket: &mut WebSocket<S>, 
                          key: &mut Key<Aes256Gcm>) -> Path where S: std::io::Read, S: std::io::Write { 
    // println!("path {:#?}", current_path.clone());
    let mut enc_path_segments: Vec<String> = get_encrypted_filenames(filename, current_path, socket, key).unwrap();     
    if enc_path_segments.len() >= 2 {
        enc_path_segments.remove(0); 
        enc_path_segments.remove(0);
        enc_path_segments.insert(0, "../FILESYSTEM".into()); 
        return Path {
            path: enc_path_segments.iter().map(|x| (true, x.into())).collect()
        }
    }
    return Path {
        path: vec![]
    }
}
