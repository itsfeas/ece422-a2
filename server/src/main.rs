use std::{borrow::{Borrow, BorrowMut}, cell::{Cell, RefCell}, env, fmt, hash::{self, Hasher}, io::Error, ops::ControlFlow, rc::Rc, sync::Arc, vec};
use std; 
use aes_gcm_siv::Aes256GcmSiv;
use dao::get_f_node;
use futures::{SinkExt, TryFutureExt};
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
use futures::future::{BoxFuture, FutureExt};
use async_recursion::async_recursion;

#[path ="./dao/dao.rs"]
mod dao;

// - https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
// - https://docs.rs/aes-gcm/latest/aes_gcm/
#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
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
    let binding = "127.0.0.1:8080".to_string();
    let addr = args.get(1)
        .unwrap_or(&binding);
    let sock = TcpListener::bind(addr).await;
    let listener = sock.expect("failed to bind");
    println!("listening on: {}", addr);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, pg_client.clone()));
    }
    Ok(())
}

async fn accept_connection(stream: TcpStream, pg_client: Arc<Mutex<Client>>) {
    dao::init_db(pg_client.clone()).await;
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
        println!("Message Received: {:?}", msg.cmd);
        match msg.cmd {
            Cmd::NewConnection => {
                key_exchange_sequence(&msg, &mut shared_secret, &mut key, &mut ws_stream).await;
                encrypted = true;
            },
            Cmd::NewUser => {
                if !authenticated { continue; }
                let user_name = msg.data.get(0).expect("username not supplied!").to_owned();
                let pass = msg.data.get(1).expect("password not supplied!").to_owned();
                let group = msg.data.get(2).expect("group not supplied!").to_owned();
                let does_user_exist = dao::get_user(pg_client.clone(), user_name.clone()).await
                    .expect("could not perform get_user query!");
                let does_group_exist = dao::get_group(pg_client.clone(), group.clone()).await
                    .expect("could not perform get_group query!").is_some();
                if !does_group_exist {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["group does not exist! you can't make an account!".to_string()]
                        }).await;
                    continue;
                }
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
                        let new_user_key = dao::create_user(pg_client.clone(), user_name.clone(), pass, Some(group), false).await.unwrap();
                        let path_str = msg.data.get(0).unwrap().to_string();
                        let new_dir_name = user_name.clone();
                        if handle_if_child_exists(&pg_client, &path_str, &new_dir_name, &mut ws_stream, &mut key).await {
                            let response = AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["please use another user name!".to_string().clone()]
                            };
                            continue;
                        }
                        let mut user_key = Arc::new(Some(new_user_key));
                        let encrypted_file_name = encrypt_string_nononce(&mut user_key, new_dir_name.clone()).unwrap();
                        let new_dir_f_node = FNode {
                            id: 0,
                            name: new_dir_name.clone(),
                            path: "/home/".to_string()+&new_dir_name.clone(),
                            owner: user_name.clone(),
                            hash: hash_file("".to_string()),
                            parent: path_str.clone(),
                            dir: true,
                            u: 7,
                            g: 7,
                            o: 0,
                            children: vec![],
                            encrypted_name: encrypted_file_name.clone()
                        };
                        let update = dao::add_file(pg_client.clone(), new_dir_f_node).await.unwrap();
                        dao::add_file_to_parent(pg_client.clone(), "/home".to_string(), new_dir_name.clone()).await;

                        let response = AppMessage {
                            cmd: Cmd::NewUser,
                            data: vec!["/home/".to_string()+&encrypted_file_name.clone()]
                        };
                        send_app_message(&mut ws_stream, &mut key, response).await;
                        continue;
                    }
                }
            },
            Cmd::NewGroup => {
                if !authenticated { continue; }
                let new_group = msg.data.get(0).expect("new group name not supplied!").to_owned();
                let res = dao::get_group(pg_client.clone(), new_group.clone()).await.unwrap();
                if res.is_some() {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["group already exists!".to_string()]
                    }).await;
                    continue;
                }
                let create_query = dao::create_group(pg_client.clone(), new_group.clone()).await.unwrap();
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::NewGroup,
                    data: vec![create_query]
                }).await;
                continue;
            },
            Cmd::Chmod => {
                if !authenticated { continue; }
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let ugo = msg.data[2].clone();
                // println!("new perms {:?}", ugo.split("").clone().into_iter().collect::<Vec<&str>>());
                let f = dao::get_f_node(pg_client.clone(),
                path_str.clone()).await.unwrap().unwrap();
                let mut perms_str: Vec<String> = ugo.split("").into_iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                if perms_str[0]=="x" {perms_str[0]=f.u.to_string()}
                if perms_str[1]=="x" {perms_str[1]=f.g.to_string()}
                if perms_str[2]=="x" {perms_str[2]=f.o.to_string()}
                let perms: Vec<i16> = perms_str.iter()
                    .map(|s| s.parse::<i16>().unwrap())
                    .collect();
                let is_owner = f.owner.eq(&(*curr_user).clone());
                if !is_owner {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["you are not the owner!".to_string()],
                    }).await;
                    continue;
                }
                dao::change_file_perms(pg_client.clone(), path_str.clone(), perms[0], perms[1], perms[2]).await;
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::Chmod,
                    data: vec![]
                }).await;
                continue;
            }
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
                        let mut owned_paths: Vec<(String, String)> = vec![]; 
                        let homenode_opt = get_f_node(pg_client.clone(), String::from("/home/") + user_name.clone().as_str()).await.unwrap();
                        // we don't search if the user doesn't own a folder, such as precreated users
                        if homenode_opt.is_some() {
                            let homenode = homenode_opt.unwrap();
                            let root_f_node = "/home".to_string();
                            search_tree_for_user(user_name.clone(), &homenode, &mut owned_paths, pg_client.clone(), root_f_node).await; 
                            // println!("PATHS OWNED BY USER: {:?}", owned_paths); 
                        };
                        AppMessage {
                            cmd: Cmd::Login,
                            data: vec![user_name.clone(), u_unwrapped.is_admin.to_string(), serde_json::to_string(&owned_paths).unwrap()],
                        }
                    },
                    ((true, Err(_)) | (false, _)) => {
                        let vec: Vec<String> = vec![];
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["failed to login!".to_string(), "".to_string(), serde_json::to_string(&vec).unwrap()],
                        }
                    },
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
                authenticated = res_auth;
            },
            Cmd::Scan => {
                if !authenticated { continue; }
                // don't run scan for directories
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let hash_existing = f_node.hash;
                let hash_new = hash_file(msg.data[1].clone());
                let msg = if hash_new.eq(&hash_existing) {
                    AppMessage {
                        cmd: Cmd::Scan,
                        data: vec![format!("Ensured integrity of {}!", path_str)],
                    }
                } else {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec![format!("Integrity of file {} compromised!", path_str)],
                    }
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
                continue;
            },
            Cmd::Cd => {
                if !authenticated { continue; }
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let target_path = msg.data.get(1).unwrap();
                // println!("parent children {:?}", f_node.children);
                let child_query = dao::get_f_node(pg_client.clone(), path_str.clone()+"/"+&msg.data[1].clone()).await
                    .expect("could not perform get_f_node query!");
                let has_read_perms = have_read_perms_for_file(&pg_client,
                    path_str.clone()+"/"+&target_path.clone(), &curr_user).await;
                if !has_read_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["do not have read permissions!".to_string()],
                    }).await;
                    continue;
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
                continue;
            },
            Cmd::Ls => {
                if !authenticated { continue; }
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
                        // println!("user {} can access file {}: {}", u.user_name.clone(), c.path.clone(), has_read_perms.clone());
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
                continue;
            },
            Cmd::Delete => {
                if !authenticated { continue; }
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let mut path_vec_enc = path_str_to_encrypted_path(path_str.clone(), &pg_client).await;
                let has_write_perms = have_write_perms_for_file(&pg_client,
                    path_str.clone(), &curr_user).await;
                if !has_write_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["do not have write permissions!".to_string()],
                    }).await;
                    continue;
                }
                dao::delete_path(pg_client.clone(), path_str).await;
                dao::remove_file_from_parent(pg_client.clone(), msg.data[0].clone(), msg.data[1].clone()).await;
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::Delete,
                    data: vec!["/home".to_string()+&path_vec_to_str(path_vec_enc)],
                }).await;
            },
            Cmd::Mv => {
                if !authenticated { continue; }
                let (old_path, old_path_str, f_node) = match get_and_check_path(msg.data[0].clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let mut old_path_vec_enc = path_str_to_encrypted_path(old_path_str.clone(), &pg_client).await;
                let new_path = msg.data[0].clone()+"/"+&msg.data[2].clone();
                let new_name = msg.data[2].clone();
                let has_write_perms = have_write_perms_for_file(&pg_client,
                    old_path_str.clone(), &curr_user).await;
                if !has_write_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["do not have write permissions!".to_string()],
                    }).await;
                    continue;
                }
                let user_key = get_key_for_file(&pg_client.clone(), old_path_str.clone(), &curr_user).await;
                dao::update_path(pg_client.clone(), old_path_str, new_path.clone()).await;
                let encrypted_name_new = encrypt_string_nononce(&mut Arc::new(user_key), new_name.clone()).unwrap();
                // println!("old_path_vec_enc {:?}", old_path_str);
                dao::update_fnode_name_if_path_is_already_updated(pg_client.clone(), new_path.clone(), new_name.clone()).await;
                dao:: update_fnode_enc_name(pg_client.clone(), new_path.clone(), encrypted_name_new.clone()).await;
                dao::remove_file_from_parent(pg_client.clone(), msg.data[0].clone(), msg.data[1].clone()).await;
                dao::add_file_to_parent(pg_client.clone(), msg.data[0].clone(), new_name).await;
                
                let mut new_path_vec_enc = old_path_vec_enc.clone();
                new_path_vec_enc.pop();
                new_path_vec_enc.push(encrypted_name_new.clone());
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::Mv,
                    data: vec!["/home".to_string()+&path_vec_to_str(old_path_vec_enc), "/home".to_string()+&path_vec_to_str(new_path_vec_enc)],
                }).await;
            },
            Cmd::Touch => {
                if !authenticated { continue; }
                let (path, path_str, f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let has_write_perms = have_write_perms_for_file(&pg_client, msg.data[0].clone(), &curr_user).await;
                if !has_write_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["do not have sufficient write privileges!".to_string()],
                    }).await;
                    continue;
                }
                let new_file_name = msg.data.get(1).unwrap();
                if handle_if_child_exists(&pg_client, &path_str, new_file_name, &mut ws_stream, &mut key).await {
                    continue;
                }
                let curr_user_key_arr: Key<Aes256Gcm> = (*curr_user_key).into();
                let mut user_key = Arc::new(Some(curr_user_key_arr));
                let encrypted_file = encrypt_string_nononce(&mut user_key, new_file_name.clone()).expect("could not encrypt file name!");
                let new_file = FNode {
                    id: -1,
                    name: new_file_name.clone(),
                    path: path_str.clone()+"/"+&new_file_name.clone(),
                    owner: (*curr_user).clone(),
                    hash: hash_file("".to_string()),
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
                if !authenticated { continue; }
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
                let f_node = dao::get_f_node(pg_client.clone(), path_str.clone()+"/"+&unencrypted_filename.clone()).await.unwrap();
                let user = dao::get_user(pg_client.clone(), (*curr_user).clone()).await.unwrap();
                let msg = match (f_node, user) {
                    (Some(f), Some(u)) => {
                        // let user_key: Key<Aes256Gcm> = (*curr_user_key).into();
                        let mut author_key = get_key_for_file(&pg_client.clone(), path_str.clone()+"/"+&unencrypted_filename.clone(), &curr_user).await;
                        let mut path_vec_enc = path_str_to_encrypted_path(path_str.clone(), &pg_client).await;
                        // let k: aes_gcm::Key<Aes256Gcm> = u.key.as_bytes();
                        // let u8_arr: aes_gcm::Key<Aes256Gcm> = u.key.as_bytes().to_vec().into();
                        let filename_enc = encrypt_string_nononce(&mut Arc::new(author_key), f.name);
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
                if !authenticated { continue; }
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
                let has_write_perms = have_write_perms_for_file(&pg_client, f_node.path.clone(), &curr_user).await;
                if !has_write_perms {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["do not have sufficient write privileges!".to_string()],
                    }).await;
                    continue;
                }

                let additional_str = msg.data.get(2).unwrap();
                let file_data = msg.data.get(3).unwrap();
                let mut author_key = Arc::new(get_key_for_file(&pg_client.clone(), msg.data[0].clone()+"/"+&msg.data[1].clone(), &curr_user).await);
                let mut plaintext_str = "".to_string();
                if !file_data.is_empty() {
                    plaintext_str += &unencrypt_string_nononce(&mut author_key, file_data).unwrap();
                }
                let new_file_str = plaintext_str.to_owned()+additional_str;
                let encrypted_file_data = encrypt_string_nononce(&mut author_key, new_file_str.clone()).unwrap();
                let new_hash = hash_file(encrypted_file_data.clone());
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
                if !authenticated { continue; }
                let (par_path, par_path_str, par_f_node) = match get_and_check_path(msg.data[0].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let (path, path_str, f_node) = match get_and_check_path(par_path_str.clone()+"/"+&msg.data[1].clone(), &pg_client, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let have_read_access = have_read_perms_for_file(&pg_client, par_path_str.clone()+"/"+&msg.data[1].clone(), &curr_user).await;
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
                // println!("received encrypted file_data {}", file_data);
                if file_data.is_empty() {
                    send_app_message(&mut ws_stream, &mut key, AppMessage {
                        cmd: Cmd::Cat,
                        data: vec!["".to_string()],
                    }).await;
                    continue;
                }
                let mut user_key = Arc::new(get_key_for_file(&pg_client.clone(), par_path_str.clone()+"/"+&msg.data[1].clone(), &curr_user).await);
                let plaintext_str = unencrypt_string_nononce(&mut user_key, file_data).unwrap();
                send_app_message(&mut ws_stream, &mut key, AppMessage {
                    cmd: Cmd::Cat,
                    data: vec![plaintext_str],
                }).await;
            },
            Cmd::Mkdir => {
                if !authenticated { continue; }
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
    // println!("path_vec {:?}", path_vec);
    path_vec = path_vec.split_off(1);
    // println!("path_vec {:?}", path_vec);
    let mut curr_path = "/home".to_string();
    let mut path_vec_enc = vec![];
    while !path_vec.is_empty() {
        curr_path += "/";
        curr_path += &path_vec.first().unwrap();
        path_vec = path_vec.split_off(1);
        // println!("new_path_vec {} {:?}", curr_path, path_vec);
        path_vec_enc.append(&mut vec![dao::get_f_node(pg_client.clone(), curr_path.clone()).await.unwrap().unwrap().encrypted_name]);
    }
    path_vec_enc
}

async fn get_and_check_path(path_str: String, pg_client: &Arc<Mutex<Client>>, ws_stream: &mut WebSocketStream<TcpStream>, key: &mut Arc<Option<Key<Aes256Gcm>>>) -> Option<(Path, String, FNode)> {
    let path: Path = Path {
        path: path_str_to_vec(path_str.clone()).iter().map(|s| (false, s.to_string())).collect()
    };
    // println!("pulling f_node with path {}", path_str.clone());
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
            // println!("DECRYPTED_MSG: {}", plaintext_str.clone());
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

#[async_recursion]
async fn search_tree_for_user(owner: String, node: &FNode, paths: &mut Vec<(String, String)>, dao_client: Arc<Mutex<Client>>, parent_enc_path: String) -> Result<(), ()> {
    let child_path_enc: String = parent_enc_path.clone()+"/"+&node.encrypted_name;
    let child_path: String = node.path.clone();
    // // search the node 
    if node.owner == owner {
        paths.push((child_path_enc.clone(), child_path.clone()));
    }
    // println!("{:?}", node.path); 

    // search children
    if node.children.len() > 0 {
        for child_name in node.children.clone() { 
            let path: String = std::path::Path::new(node.path.as_str()).join(child_name).to_str().unwrap().into();
            let child_fnode_opt = get_f_node(dao_client.clone(), path).await.unwrap();
            if child_fnode_opt.is_none() {
                continue;
            }
            let child_fnode = child_fnode_opt.unwrap();
            search_tree_for_user(owner.clone(), &child_fnode, paths, dao_client.clone(), child_path_enc.clone()).await; 
        }
    }

    Ok(())
}

async fn key_exchange_sequence(msg: &AppMessage, shared_secret: &mut Arc<Option<Arc<SharedSecret>>>, key: &mut Arc<Option<Key<Aes256Gcm>>>, ws_stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>) {
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let client_public: PublicKey = serde_json::from_str(&msg.data[0]).unwrap();
    *shared_secret = Arc::new(Some(Arc::new(server_secret.diffie_hellman(&client_public))));
    let ref_cell = Option::clone(shared_secret.as_ref());
    let key_arr: [u8; 32] = ref_cell.unwrap().to_bytes();
    // println!("client_shared_key {:?}", key_arr);
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

fn hash_file(file_data: String) -> String {
    let mut hasher = blake3::Hasher::new();
    // hasher.update(file_new.as_bytes());
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
    // println!("get key for file {} for user {}", path_str.clone(), curr_user_name.clone());
    let f_node_opt = dao::get_f_node(pg_client.clone(), path_str.clone()).await.unwrap();
    let f_node = match f_node_opt {
        Some(f) => f,
        None => {
            // println!("can't find owner for file {}", path_str.clone());
            return None
        }
    };
    // println!("key_path_str {}, p0", path_str.clone());
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    if curr_user_name.is_empty() {
        // println!("key_path_str {}, p1", path_str.clone());
        return None;
    }
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.o & 0b100)>0 {
        // get f_node owner key
        // println!("key_path_str {}, p2", path_str.clone());
        return get_user_key_from_user(&owner_user);
    } else if (f_node.u & 0b100)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        // println!("key_path_str {}, p3", path_str.clone());
        return get_user_key_from_user(&curr_user);
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        // println!("key_path_str {}, p4", path_str.clone());
        return None;
    } else if (f_node.g & 0b100)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        // println!("key_path_str {}, p5", path_str.clone());
        return get_user_key_from_user(&owner_user);
    }
    None
}

async fn have_write_perms_for_file(pg_client: &Arc<Mutex<Client>>,
        path_str: String, curr_user_name: &Arc<String>) -> bool {
    // println!("w_path_str {}, p0", path_str.clone());
    let f_node_opt = dao::get_f_node(pg_client.clone(), path_str.clone()).await.unwrap();
    let f_node = match f_node_opt {
        Some(f) => f,
        None => return false
    };
    if (f_node.o & 0b010)>0 {
        // get f_node owner key
        // println!("w_path_str {}, p1", path_str.clone());
        return true;
    };
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.u & 0b010)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        // println!("w_path_str {}, p2", path_str.clone());
        return true;
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        // println!("w_path_str {}, p3", path_str.clone());
        return false;
    } else if (f_node.g & 0b010)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        // println!("w_path_str {}, p4", path_str.clone());
        return true;
    }
    // println!("w_path_str {}, p5", path_str.clone());
    false
}

async fn have_read_perms_for_file(pg_client: &Arc<Mutex<Client>>, path_str: String, curr_user_name: &Arc<String>) -> bool {
    // println!("path_str {}, p0", path_str.clone());
    let f_node_opt = dao::get_f_node(pg_client.clone(), path_str.clone()).await.unwrap();
    let f_node = match f_node_opt {
        Some(f) => f,
        None => return false
    };
    if (f_node.o & 0b100)>0 {
        // println!("path_str {}, p1", path_str.clone());
        return true;
    };
    let curr_user = dao::get_user(pg_client.clone(), (**curr_user_name).clone()).await.unwrap().unwrap();
    let owner_user_name = f_node.owner;
    let owner_user = dao::get_user(pg_client.clone(), owner_user_name.clone()).await.unwrap().unwrap();
    if (f_node.u & 0b100)>0 && owner_user_name.eq(&(**curr_user_name).clone()) {
        // println!("path_str {}, p2", path_str.clone());
        return true;
    } else if curr_user.group_name.is_none() || owner_user.group_name.is_none() {
        // println!("path_str {}, p3", path_str.clone());
        return false;
    } else if (f_node.g & 0b100)>0 && curr_user.group_name.unwrap().eq(&owner_user.group_name.clone().unwrap()) {
        // println!("path_str {}, p4", path_str.clone());
        return true;
    }
    // println!("path_str {}, p5", path_str.clone());
    false
}

fn path_vec_to_str(path: Vec<String>) -> String {
    let mut path_string = path.iter().map(|x| {
                x.clone()
            }).filter(|x| x != "/").collect::<Vec<String>>().join("/");

    path_string.insert_str(0, "/"); 
    format!("{}", path_string)
}