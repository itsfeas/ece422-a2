use std::{borrow::{Borrow, BorrowMut}, cell::{Cell, RefCell}, io::Error, ops::ControlFlow, rc::Rc, sync::Arc};
use futures::SinkExt;
use futures_util::{future, StreamExt, TryStreamExt};
use tokio::{net::{TcpListener, TcpStream}, sync::Mutex};
use log::info;
use tokio_postgres::{Client, NoTls};
use model::model::{AppMessage, Cmd, Path, FNode};
use tokio_tungstenite::{tungstenite::{http::response, Message}, WebSocketStream};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand_core::OsRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use std::str::from_utf8;

#[path ="./dao/dao.rs"]
mod dao;

// - https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
// - https://docs.rs/aes-gcm/latest/aes_gcm/
#[tokio::main]
async fn main() -> Result<(), Error> {
    let (client, connection) =
        tokio_postgres::connect("host=localhost user=postgres", NoTls).await
        .expect("Could not form connection with DB!");
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

    let mut encrypted = false;
    let mut authenticated = false;
    while let Some(m) = ws_stream.next().await {
        let m = m.expect("panicked while checking validity of message");
        if !m.is_text() && m.is_binary() {
            continue;
        }
        let msg_serialized = m.to_string();

        println!("SERIALIZED_MSG: {}", msg_serialized);
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
                match does_user_exist.is_none() {
                    true => {
                        let response = AppMessage {
                            cmd: Cmd::Failure,
                            data: Vec::new()
                        };
                        send_app_message(&mut ws_stream, &mut key, response).await;
                        continue;
                    },
                    false => {
                        dao::create_user(pg_client.clone(), user_name, pass, None, false).await.expect("could not create user!");
                        let response = AppMessage {
                            cmd: Cmd::NewUser,
                            data: Vec::new()
                        };
                        send_app_message(&mut ws_stream, &mut key, response).await;
                        continue;
                    }
                }
            },
            Cmd::Login => {
                let user_name = msg.data.get(0).expect("username not supplied!").to_owned();
                let pass = msg.data.get(1).expect("password not supplied!").to_owned();
                let res = dao::auth_user(pg_client.clone(), user_name.clone(), pass).await
                    .expect("could not perform auth_user query!");
                curr_user = Arc::new(user_name.clone());
                authenticated = res;
            },
            Cmd::Cd => {
                let path: Path = serde_json::from_str(msg.data.get(0).unwrap()).unwrap();
                let path_str = path_to_str(path);
                let target_path = msg.data.get(1).unwrap();
                let res = dao::get_f_node(pg_client.clone(), path_str+msg.data.get(1).unwrap()).await
                    .expect("could not perform get_f_node query!");
                let f_node = match check_curr_path(res, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                if f_node.children.contains(target_path) {
                    let msg = AppMessage {
                        cmd: Cmd::Cd,
                        data: vec![target_path.clone()],
                    };
                    send_app_message(&mut ws_stream, &mut key, msg).await;
                    continue;
                }
            },
            Cmd::Ls => {
                let path: Path = serde_json::from_str(msg.data.get(0).unwrap()).unwrap();
                let path_str = path_to_str(path);
                let target_path = msg.data.get(1).unwrap();
                let res = dao::get_f_node(pg_client.clone(), path_str+msg.data.get(1).unwrap()).await
                    .expect("could not perform get_f_node query!");
                let f_node = match check_curr_path(res, &mut ws_stream, &mut key).await {
                    Some(value) => value,
                    None => continue,
                };
                let msg = AppMessage {
                    cmd: Cmd::Ls,
                    data: f_node.children,
                };
                send_app_message(&mut ws_stream, &mut key, msg).await;
            }
            _ => todo!()
        }
    }
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
    if f_node.dir {
        let msg = AppMessage {
            cmd: Cmd::Failure,
            data: vec!["Current path is not a directory!".to_string()],
        };
        send_app_message(ws_stream, key, msg).await;
        return None;
    }
    Some(f_node)
}

fn encrypt_msg(key: &mut Arc<Option<Key<Aes256Gcm>>>, msg: &AppMessage) -> Result<String, ()> {
    let msg_serialized = serde_json::to_string(msg).unwrap();
    let cipher = Aes256Gcm::new(&(*key).unwrap());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypt = cipher.encrypt(&nonce, msg_serialized.as_ref());
    match encrypt {
        Ok(e) => Ok(from_utf8(&e).unwrap().to_string()),
        Err(_) => Err(()),
    }
}

fn handle_msg(encrypted: bool, key: &mut Arc<Option<Key<Aes256Gcm>>>, msg_serialized: String) -> AppMessage {
    match encrypted {
        true => {
            let cipher = Aes256Gcm::new(&(*key).unwrap());
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let plaintext = cipher.decrypt(&nonce, msg_serialized.as_ref()).unwrap();
            let plaintext_str = from_utf8(&plaintext).unwrap();
            serde_json::from_str(&plaintext_str).unwrap()
        },
        false => serde_json::from_str(&msg_serialized).unwrap(),
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
    let resp_encrypted = encrypt_msg(key, &resp);
    ws_stream.send(Message::text(serde_json::to_string(&resp_encrypted).unwrap())).await.unwrap();
}

fn path_to_str(path: Path) -> String {
    let mut path_str: String = path.path[0].1.clone();
    path.path[1..].into_iter()
        .map(|t| t.1.clone()+"/")
        .for_each(|s| path_str+= &s);
    path_str
}