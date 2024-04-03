use std::{borrow::{Borrow, BorrowMut}, cell::{Cell, RefCell}, env, fmt, hash::{self, Hasher}, io::Error, ops::ControlFlow, rc::Rc, sync::Arc, vec};
use aes_gcm_siv::Aes256GcmSiv;
use futures::SinkExt;
use futures_util::{future, StreamExt, TryStreamExt};
use tokio::{net::{TcpListener, TcpStream}, sync::Mutex};
use log::info;
use tokio_postgres::{Client, Config, NoTls};
use model::model::{AppMessage, Cmd, FNode, Path, User};
use tokio_tungstenite::{tungstenite::{http::response, Message}, WebSocketStream};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand_core::OsRng;
use aes_gcm::{
    aead::{consts::U12, Aead, AeadCore, KeyInit}, Aes256Gcm, Key, Nonce
};
use std::str::from_utf8;

#[path ="./dao/dao.rs"]
mod dao;

// - https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
// - https://docs.rs/aes-gcm/latest/aes_gcm/
#[tokio::main]
async fn main() -> Result<(), Error> {
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let (client, connection) =
        tokio_postgres::connect(&format!("host=localhost dbname=db user=USER password={} port=5431", db_pass), NoTls).await
        .unwrap();
    let pg_client = Arc::new(Mutex::new(client));
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });
    // println!("Hello, world!");
    let addr = "127.0.0.1:8080";
    // let sock = TcpListener
    let sock = TcpListener::bind(addr).await;
    let listener = sock.expect("failed to bind");
    println!("listening on: {}", addr);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, pg_client.clone()));
    }
    Ok(())
}

async fn accept_connection(stream: TcpStream, pg_client: Arc<Mutex<Client>>) {
    let addr = stream.peer_addr().expect("could not find peer address!");
    println!("peer: {}", addr);
    
    let mut ws_stream = tokio_tungstenite::accept_async(stream).await.expect("error during websocket handshake!");
    println!("New WebSocket connection: {}", addr);

    let mut shared_secret: Arc<Option<Arc<SharedSecret>>> = Arc::new(None);
    let mut key: Arc<Option<Key<Aes256Gcm>>> = Arc::new(None);
    let mut curr_user : Arc<String> = Arc::new(String::new());
    let mut curr_user_key : Arc<Key<Aes256Gcm>> = Arc::new(Aes256Gcm::generate_key(&mut OsRng));

    let mut encrypted = false;
    let mut authenticated = false;
    let mut echo_accepting_data = false;
    let mut dual_msg_flag = false;
    while let Some(m) = ws_stream.next().await {
        let m = m.unwrap();
        if !m.is_text() && m.is_binary() {
            continue;
        }
        let msg_serialized = m.to_string();

        // println!("SERIALIZED_MSG: {}", msg_serialized);
        let msg: AppMessage = handle_msg(encrypted, &mut key, msg_serialized);
        match msg.cmd {
            Cmd::NewConnection => {
                key_exchange_sequence(&msg, &mut shared_secret, &mut key, &mut ws_stream).await;
                encrypted = true;
            },
            Cmd::NewUser => {
                let user_name = msg.data.get(0).expect("username not supplied!").to_owned();
                let pass = msg.data.get(1).expect("password not supplied!").to_owned();
                let does_user_exist = dao::get_user(pg_client.clone(), user_name.clone()).await
                    .expect("could not perform get_user query!");
                match does_user_exist.is_some() {
                    true => {
                        let response = AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["user already exists! you can't make an account!".to_string()]
                        };
                        send_app_message(&mut ws_stream, &mut key, response).await;
                        continue;
                    },
                    false => {
                        curr_user_key = Arc::new(dao::create_user(pg_client.clone(), user_name.clone(), pass, None, true).await.unwrap());
                        let response = AppMessage {
                            cmd: Cmd::NewUser,
                            data: vec![user_name.clone()]
                        };
                        authenticated = true;
                        curr_user = Arc::new(user_name.clone());
                        send_app_message(&mut ws_stream, &mut key, response).await;
                        continue;
                    }
                }
            },
            Cmd::Login => {
                let user_name = msg.data.get(0).expect("username not supplied!").to_owned();
                let pass = msg.data.get(1).expect("password not supplied!").to_owned();
                let res_auth = dao::auth_user(pg_client.clone(), user_name.clone(), pass).await
                    .expect("could not perform auth_user query!");
                let res_user = dao::get_user(pg_client.clone(), user_name.clone()).await;
                let msg = match (res_auth, res_user) {
                    (true, Ok(u)) => {
                        curr_user = Arc::new(user_name.clone());
                        let u_unwrapped = u.unwrap();
                        curr_user_key = Arc::new(serde_json::from_str::<[u8; 32]>(&u_unwrapped.key).unwrap().into());
                        AppMessage {
                            cmd: Cmd::Login,
                            data: vec![user_name.clone(), u_unwrapped.is_admin.to_string()],
                        }
                    },
                    ((true, Err(_)) | (false, _)) => {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["failed to login!".to_string()],
                        }
                    },
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
                authenticated = res_auth;
            },
            Cmd::Cd => {
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let target_path = msg.data.get(1).unwrap();
                println!("parent children {:?}", f_node.children);
                let child_query = dao::get_f_node(pg_client.clone(), path_str.clone()+"/"+&msg.data[1].clone()).await
                    .expect("could not perform get_f_node query!");
                let has_read_perms = have_read_perms_for_file(&pg_client,
                    path_str.clone()+"/"+&target_path.clone(), &curr_user).await;
                if !has_read_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["do not have read permissions!".to_string()],
                    }).await;
                }
                let parent_contains = f_node.children.contains(target_path);
                let resp = if parent_contains && child_query.is_some() && child_query.unwrap().dir {
                    AppMessage {
                        cmd: Cmd::Cd,
                        data: vec![target_path.clone()],
                    }
                } else if parent_contains {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["path is not a directory!".to_string()],
                    }
                } else {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["target_path could not be found in parent path".to_string()],
                    }
                };
                send_app_message(&mut ws_stream, &mut key, resp).await;
            },
            Cmd::Ls => {
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let has_read_perms = have_read_perms_for_file(&pg_client,
                    path_str.clone(), &curr_user).await;
                if !has_read_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["do not have read permissions!".to_string()],
                    }).await;
                    continue;
                }
                let children: Vec<String> = futures::stream::iter(f_node.children)
                    .then(|c| dao::get_f_node(pg_client.clone(), path_str.clone()+"/"+&c))
                    .then(|c| future::ready(c.unwrap()))
                    .filter(|c| future::ready(c.is_some()))
                    .then(|c| future::ready(c.unwrap()))
                    .then(|c| async {
                        let u = dao::get_user(pg_client.clone(), c.owner.clone()).await.unwrap().unwrap();
                        future::ready((u, c))
                    })
                    .then(|e| async {
                        let (u, c) = e.await;
                        let has_read_perms = have_read_perms_for_file(&pg_client, c.path.clone(), &curr_user).await;
                        println!("user {} can access file {}: {}", u.user_name.clone(), c.path.clone(), has_read_perms.clone());
                        if has_read_perms {
                            c.name
                        } else {
                            c.encrypted_name
                        }
                    })
                    .collect()
                    .await;
                let msg = AppMessage {
                    cmd: Cmd::Ls,
                    data: children,
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
            },
            Cmd::Touch => {
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let new_file_name = msg.data.get(1).unwrap();
                if handle_if_child_exists(&pg_client, &path_str, new_file_name, &mut ws_stream, &mut key).await {
                    continue;
                }
                let mut user_key = Arc::new(get_user_key(&pg_client, &curr_user).await);
                let encrypted_file = encrypt_string_nononce(&mut user_key, new_file_name.clone()).expect("could not encrypt file name!");
                let new_file = FNode {
                    id: -1,
                    name: new_file_name.clone(),
                    path: path_str.clone()+"/"+&new_file_name.clone(),
                    owner: (*curr_user).clone(),
                    hash: "".to_string(),
                    parent: path_str.clone()[..path_str.len()-2].to_string(),
                    dir: false,
                    u: 7,
                    g: 0,
                    o: 0,
                    children: vec![],
                    encrypted_name: encrypted_file.clone()
                };
                let mut resp = match dao::add_file(pg_client.clone(), new_file).await {
                    Ok(file_name) => {
                        AppMessage {
                            cmd: Cmd::Touch,
                            data: vec![encrypted_file],
                        }
                    },
                    Err(_) => {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["FNode could not be created!".to_string()],
                        }
                    },
                };
                match dao::add_file_to_parent(pg_client.clone(), path_str.clone(), new_file_name.clone()).await {
                    Ok(_) => {},
                    Err(_) => {
                        resp = AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["FNode parent could not be updated!".to_string()],
                        }
                    },
                };
                send_app_message(&mut ws_stream, &mut key, resp).await;
            },
            Cmd::GetEncryptedFile => {
                let path_str = msg.data[0].to_string();
                let unencrypted_filename = msg.data[1].clone();
                let have_read_access = have_read_perms_for_file(&pg_client, path_str.clone()+"/"+&unencrypted_filename, &curr_user).await;
                if !have_read_access {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["don't have read access!".to_string()],
                    }).await;
                    continue;
                }
                let f_node = dao::get_f_node(pg_client.clone(), path_str.clone()+"/"+&unencrypted_filename).await.unwrap();
                let user = dao::get_user(pg_client.clone(), (*curr_user).clone()).await.unwrap();
                let msg = match (f_node, user) {
                    (Some(f), Some(u)) => {
                        let user_key: Key<Aes256Gcm> = (*curr_user_key).into();
                        let mut path_vec_enc = path_str_to_encrypted_path(path_str.clone(), &pg_client).await;
                        // let k: aes_gcm::Key<Aes256Gcm> = u.key.as_bytes();
                        // let u8_arr: aes_gcm::Key<Aes256Gcm> = u.key.as_bytes().to_vec().into();
                        let filename_enc = encrypt_string_nononce(&mut Arc::new(Some(user_key)), f.name);
                        path_vec_enc.append(&mut vec![filename_enc.unwrap()]);
                        let mut full_path_vec = vec!["/".to_string(), "home".to_string()];
                        full_path_vec.append(&mut path_vec_enc);
                        AppMessage {
                            cmd: Cmd::GetEncryptedFile,
                            data: full_path_vec,
                        }
                    },
                    (Some(_), _) => AppMessage {
                            cmd: Cmd::Touch,
                            data: vec!["could not get encrypted filename (but f_node exists)!".to_string()],
                        },
                    (_, Some(_)) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["could not get encrypted filename (but user exists)!".to_string()],
                        },
                    (_, _) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["could not get encrypted filename (but and neither user or f_node exist)!".to_string()],
                    },
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
            },
            Cmd::Echo => {
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                if f_node.dir {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["can't write to a directory!".to_string()],
                    }).await;
                    continue;
                };
                let additional_str = msg.data.get(2).unwrap();
                let file_data = msg.data.get(3).unwrap();
                let mut user_key = Arc::new(get_user_key(&pg_client.clone(), &curr_user).await);
                let mut plaintext_str = "".to_string();
                if !file_data.is_empty() {
                    plaintext_str += &unencrypt_string_nononce(&mut user_key, file_data).unwrap();
                }
                let new_file_str = plaintext_str.to_owned()+additional_str;
                let encrypted_file_data = encrypt_string_nononce(&mut user_key, new_file_str.clone()).unwrap();
                let new_hash = hash_file(f_node.name.clone(), new_file_str.clone());
                let update = dao::update_hash(pg_client.clone(), path_str, f_node.name, new_hash).await;
                let resp = match update {
                    Ok(_) => AppMessage {
                            cmd: Cmd::Echo,
                            data: vec![encrypted_file_data],
                        },
                    Err(_) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["could not update hash!".to_string()],
                        },
                };
                send_app_message(&mut ws_stream, &mut key, resp).await;
            },
            Cmd::Cat => {
                let (par_path, par_path_str, par_f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let (path, path_str, f_node) = match get_and_check_path(par_path_str.clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let have_read_access = have_read_perms_for_file(&pg_client, par_path_str+"/"+&msg.data[1].clone(), &curr_user).await;
                if !have_read_access {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["don't have read access!".to_string()],
                    }).await;
                    continue;
                };
                if f_node.dir {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["cannot cat a directory!".to_string()],
                    }).await;
                    continue;
                }
                let file_data = msg.data.get(2).unwrap();
                println!("received encrypted file_data {}", file_data);
                if file_data.is_empty() {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Cat,
                        data: vec!["".to_string()],
                    }).await;
                    continue;
                }
                let mut user_key = Arc::new(get_user_key(&pg_client.clone(), &curr_user).await);
                let plaintext_str = unencrypt_string_nononce(&mut user_key, file_data).unwrap();
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::Cat,
                    data: vec![plaintext_str],
                }).await;
            },
            Cmd::Mkdir => {
                let path_str = msg.data.get(0).unwrap().to_string();
                let new_dir_name = msg.data.get(1).unwrap();
                if handle_if_child_exists(&pg_client, &path_str, new_dir_name, &mut ws_stream, &mut key).await {
                    continue;
                }
                let user_key: Key<Aes256Gcm> = (*curr_user_key).into();
                let mut user_key = Arc::new(Some(user_key));
                let encrypted_file_name = encrypt_string_nononce(&mut user_key, new_dir_name.clone()).unwrap();
                let new_dir_f_node = FNode {
                    id: 0,
                    name: new_dir_name.clone(),
                    path: path_str.clone()+"/"+&new_dir_name.clone(),
                    owner: (*curr_user).to_string(),
                    hash: "".to_string(),
                    parent: path_str.clone(),
                    dir: true,
                    u: 7,
                    g: 0,
                    o: 0,
                    children: vec![],
                    encrypted_name: encrypted_file_name.clone()
                };
                let update = dao::add_file(pg_client.clone(), new_dir_f_node).await;
                let mut resp = match update {
                    Ok(_) => AppMessage {
                            cmd: Cmd::Mkdir,
                            data: vec![encrypted_file_name.clone()],
                        },
                    Err(err) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec![err.to_string()],
                        },
                };
                match dao::add_file_to_parent(pg_client.clone(), path_str.clone(), new_dir_name.clone()).await {
                    Ok(_) => {},
                    Err(_) => {
                        resp = AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["FNode parent could not be updated!".to_string()],
                        }
                    },
                };
                send_app_message(&mut ws_stream, &mut key, resp).await;
            },
            _ => todo!()
        }
    }
}

async fn handle_if_child_exists(pg_client: &Arc<Mutex<Client>>, path_str: &String,
    new_file_name: &String, ws_stream: &mut WebSocketStream<TcpStream>, key: &mut Arc<Option<Key<Aes256Gcm>>>) -> bool {
    if {
        let pg_client = pg_client.clone();
        let path_str = path_str.clone()+"/"+&new_file_name.clone();
        async move {
            dao::get_f_node(pg_client.clone(), path_str).await
                .expect("could not perform get_f_node query!")
                .is_some()
        }
    }.await {
        send_app_message(ws_stream, key, AppMessage {
            cmd: Cmd::Failure,
            data: vec!["file/directory with this name already exists!".to_string()],
        }).await;
        return true;
    }
    false
}

async fn path_str_to_encrypted_path(path_str: String, pg_client: &Arc<Mutex<Client>>) -> Vec<String> {
    let mut path_vec = path_str_to_vec(path_str.clone());
    println!("path_vec {:?}", path_vec);
    path_vec = path_vec.split_off(1);
    println!("path_vec {:?}", path_vec);
    let mut curr_path = "/home".to_string();
    let mut path_vec_enc = vec![];
    while !path_vec.is_empty() {
        curr_path += "/";
        curr_path += &path_vec.first().unwrap();
        path_vec = path_vec.split_off(1);
        println!("new_path_vec {} {:?}", curr_path, path_vec);
        path_vec_enc.append(&mut vec![dao::get_f_node(pg_client.clone(), curr_path.clone()).await.unwrap().unwrap().encrypted_name]);
    }
    path_vec_enc
}

async fn get_and_check_path(path_str: String, pg_client: &Arc<Mutex<Client>>, ws_stream: &mut WebSocketStream<TcpStream>, key: &mut Arc<Option<Key<Aes256Gcm>>>) -> Option<(Path, String, FNode)> {
    let path: Path = Path {
        path: path_str_to_vec(path_str.clone()).iter().map(|s| (false, s.to_string())).collect()
    };
    println!("pulling f_node with path {}", path_str.clone());
    let res = dao::get_f_node(pg_client.clone(), path_str.clone()).await
        .expect("could not perform get_f_node query!");
    let f_node = match check_curr_path(res, ws_stream, key).await {
        Some(value) => value,
        None => return None,
    };
    Some((path, path_str, f_node))
}

async fn check_curr_path(res: Option<FNode>, ws_stream: &mut WebSocketStream<TcpStream>, key: &mut Arc<Option<Key<Aes256Gcm>>>) -> Option<FNode> {
    let f_node = match res {
        Some(f_node) => {
            f_node
        },
        None => {
            let msg = AppMessage {
                cmd: Cmd::Failure,
                data: vec!["Current path does not exist!".to_string()],
            };
            send_app_message(ws_stream, key, msg).await;
            return None;
        },
    };
    // if !f_node.dir {
    //     let msg = AppMessage {
    //         cmd: Cmd::Failure,
    //         data: vec!["Current path is not a directory!".to_string()],
    //     };
    //     send_app_message(ws_stream, key, msg).await;
    //     return None;
    // }
    Some(f_node)
}


fn encrypt_msg(key: &mut Arc<Option<Key<Aes256Gcm>>>, msg: &AppMessage) -> Result<(String, [u8;12]), ()> {
    let msg_serialized = serde_json::to_string(msg).unwrap();
    encrypt_string(key, msg_serialized)
}

fn encrypt_string(key: &mut Arc<Option<Key<Aes256Gcm>>>, s: String) -> Result<(String, [u8;12]), ()> {
    let cipher = Aes256Gcm::new(&(*key).unwrap());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypt = cipher.encrypt(&nonce, s.as_ref());
    match encrypt {
        Ok(e) => Ok((hex::encode(&e), nonce.into())),
        Err(_) => Err(()),
    }
}

fn encrypt_string_nononce(key: &mut Arc<Option<Key<Aes256Gcm>>>, s: String) -> Result<String, ()> {
    let cipher = Aes256Gcm::new(&(*key).unwrap());
    let nonce: Nonce<U12> = [0,0,0,0,0,0,0,0,0,0,0,0].into();
    let encrypt = cipher.encrypt(&nonce, s.as_ref());
    match encrypt {
        Ok(e) => Ok(hex::encode(e)),
        Err(_) => Err(()),
    }
}

fn handle_msg(encrypted: bool, key: &mut Arc<Option<Key<Aes256Gcm>>>, msg_serialized: String) -> AppMessage {
    match encrypted {
        true => {
            let plaintext_str = unencrypt_string(key, &msg_serialized).unwrap();
            println!("DECRYPTED_MSG: {}", plaintext_str.clone());
            serde_json::from_str(&plaintext_str).unwrap()
        },
        false => serde_json::from_str(&msg_serialized).unwrap(),
    }
}

fn unencrypt_string(key: &mut Arc<Option<Key<Aes256Gcm>>>, encrypted_str: &String) -> Result<String, ()> {
    let cipher = Aes256Gcm::new(&(*key).unwrap());
    let msg_tup: (String, [u8;12]) = serde_json::from_str(&encrypted_str).unwrap();
    let encrypted_u8: Vec<u8> = hex::decode(&msg_tup.0).unwrap();
    let nonce: aes_gcm::Nonce<U12> = msg_tup.1.into();
    match cipher.decrypt(&nonce, encrypted_u8.as_ref()) {
        Ok(plaintext) => Ok(from_utf8(&plaintext.to_owned()).unwrap().to_string()),
        Err(_) => Err(()),
    }
}

fn unencrypt_string_nononce(key: &mut Arc<Option<Key<Aes256Gcm>>>, encrypted_str: &String) -> Result<String, ()> {
    let cipher = Aes256Gcm::new(&(*key).unwrap());
    let encrypted_u8: Vec<u8> = hex::decode(&encrypted_str).unwrap();
    let nonce: Nonce<U12> = [0,0,0,0,0,0,0,0,0,0,0,0].into();
    match cipher.decrypt(&nonce, encrypted_u8.as_ref()) {
        Ok(plaintext) => Ok(from_utf8(&plaintext.to_owned()).unwrap().to_string()),
        Err(_) => Err(()),
    }
}

async fn key_exchange_sequence(msg: &AppMessage, shared_secret: &mut Arc<Option<Arc<SharedSecret>>>, key: &mut Arc<Option<Key<Aes256Gcm>>>, ws_stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>) {
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let client_public: PublicKey = serde_json::from_str(&msg.data[0]).unwrap();
    *shared_secret = Arc::new(Some(Arc::new(server_secret.diffie_hellman(&client_public))));
    let ref_cell = Option::clone(shared_secret.as_ref());
    let key_arr: [u8; 32] = ref_cell.unwrap().to_bytes();
    println!("client_shared_key {:?}", key_arr);
    *key = Arc::new(Some(key_arr.into()));
    let reply = AppMessage{
        cmd: Cmd::NewConnection,
        data: vec![serde_json::to_string(&server_public).unwrap()]
    };
    ws_stream.send(Message::text(serde_json::to_string(&reply).unwrap())).await.unwrap();
}

// async fn login_sequence(msg: &AppMessage, ws_stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> Result<bool, ()> {
//     let salt = SaltString::generate(&mut OsRng);
//     let argon2 = Argon2::default();
//     let password_hash = argon2.hash_password(msg.data[0], &salt)?.to_string();

//     let reply = AppMessage{
//         cmd: Cmd::New,
//         data: vec![serde_json::to_string(&server_public).unwrap()]
//     };
//     send_app_message(ws_stream, reply).await;
// }

async fn send_app_message(ws_stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>, key: &mut Arc<Option<Key<Aes256Gcm>>>, resp: AppMessage) {
    let resp_encrypted = encrypt_msg(key, &resp).unwrap();
    ws_stream.send(Message::text(serde_json::to_string(&resp_encrypted).unwrap())).await.unwrap();
}

fn hash_file(file_new: String, file_data: String) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(file_new.as_bytes());
    hasher.update(file_data.as_bytes());
    hasher.finalize().to_string()
}

fn path_to_str(path: Path) -> String {
    let mut path_str: String = path.path[0].1.clone();
    path.path[1..].into_iter()
        .map(|t| t.1.clone()+"/")
        .for_each(|s| path_str+= &s);
    path_str
}

fn path_str_to_vec(path: String) -> Vec<String> {
    let mut path_vec: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
    path_vec.remove(0);
    path_vec
}

async fn get_user_key(pg_client: &Arc<Mutex<Client>>, curr_user: &Arc<String>) -> Option<Key<Aes256Gcm>> {
    let user = dao::get_user(pg_client.clone(), (**curr_user).clone()).await.unwrap();
    let key_str = user.unwrap().key;
    match serde_json::from_str::<[u8; 32]>(&key_str) {
        Ok(k) => Some(k.into()),
        Err(_) => None,
    }
}

fn get_user_key_from_user(user: &User) -> Option<Key<Aes256Gcm>> {
    let key_str = user.key.clone();
    match serde_json::from_str::<[u8; 32]>(&key_str) {
        Ok(k) => Some(k.into()),
        Err(_) => None,
    }
}


async fn get_key_for_file(pg_client: &Arc<Mutex<Client>>, path_str: String, curr_user_name: &Arc<String>) -> Option<Key<Aes256Gcm>> {
    println!("get key for file {}", path_str);
    let f_node = dao::get_f_node(pg_client.clone(), path_str).await.unwrap().unwrap();
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    if curr_user_name.is_empty() {
        return None;
    }
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.o & 0b100)>0 {
        // get f_node owner key
        return get_user_key_from_user(&owner_user);
    } else if (f_node.u & 0b100)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        return get_user_key_from_user(&curr_user);
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        return None;
    } else if (f_node.g & 0b100)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        return get_user_key_from_user(&owner_user);
    }
    None
}

async fn have_write_perms_for_file(pg_client: &Arc<Mutex<Client>>,
        path_str: String, curr_user_name: &Arc<String>) -> bool {
    let f_node = dao::get_f_node(pg_client.clone(), path_str).await.unwrap().unwrap();
    if (f_node.o & 0b010)>0 {
        // get f_node owner key
        return true;
    };
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.u & 0b010)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        return true;
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        return false;
    } else if (f_node.g & 0b010)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        return true;
    }
    false
}

async fn have_read_perms_for_file(pg_client: &Arc<Mutex<Client>>, path_str: String, curr_user_name: &Arc<String>) -> bool {
    println!("path_str {}, p0", path_str.clone());
    let f_node = dao::get_f_node(pg_client.clone(), path_str.clone()).await.unwrap().unwrap();
    if (f_node.o & 0b100)>0 {
        println!("path_str {}, p1", path_str.clone());
        return true;
    };
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.u & 0b100)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        println!("path_str {}, p2", path_str.clone());
        return true;
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        println!("path_str {}, p3", path_str.clone());
        return false;
    } else if (f_node.g & 0b100)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        println!("path_str {}, p4", path_str.clone());
        return true;
    }
    println!("path_str {}, p5", path_str.clone());
    false
}