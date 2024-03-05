use std::{borrow::{Borrow, BorrowMut}, cell::{Cell, RefCell}, io::Error, rc::Rc, sync::Arc};
use futures::SinkExt;
use futures_util::{future, StreamExt, TryStreamExt};
use tokio::net::{TcpListener, TcpStream};
use log::info;
use postgres::{Client, NoTls};
use model::model::AppMessage;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand_core::OsRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use std::str::from_utf8;

// - https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
// - https://docs.rs/aes-gcm/latest/aes_gcm/
#[tokio::main]
async fn main() -> Result<(), Error> {
    // let mut client = Client::connect("host=localhost user=postgres", NoTls)?;
    // println!("Hello, world!");
    let addr = "127.0.0.1:8080";
    // let sock = TcpListener
    let sock = TcpListener::bind(addr).await;
    let listener = sock.expect("failed to bind");
    println!("listening on: {}", addr);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream));
    }
    Ok(())
}

async fn accept_connection(stream: TcpStream) {
    let addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => panic!("could not find peer address!")
    };
    println!("peer: {}", addr);
    
    let mut ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(v) => v,
        Err(e) => panic!("error during websocket handshake!: {}", e),
    };
    println!("New WebSocket connection: {}", addr);

    let mut shared_secret: Arc<Option<Arc<SharedSecret>>> = Arc::new(None);
    let mut key: Arc<Option<Key<Aes256Gcm>>> = Arc::new(None);

    // let (mut w, mut r) = ws_stream.split();
    let mut authenticated = false;
    while let Some(m) = ws_stream.next().await {
        let m = match m {
            Ok(m) => m,
            Err(e) => panic!("panicked while checking validity of message {}", e),
        };
        if !m.is_text() && m.is_binary() {
            continue;
        }
        let msg_serialized = m.to_string();

        println!("SERIALIZED_MSG: {}", msg_serialized);
        let msg: AppMessage = match authenticated {
            true => {
                let cipher = Aes256Gcm::new(&(*key).unwrap());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let plaintext = cipher.decrypt(&nonce, msg_serialized.as_ref()).unwrap();
                let plaintext_str = from_utf8(&plaintext).unwrap();
                serde_json::from_str(&plaintext_str).unwrap()
            },
            false => serde_json::from_str(&msg_serialized).unwrap(),
        };
        match msg.cmd.as_str() {
            "new" => {
                let server_secret = EphemeralSecret::random_from_rng(OsRng);
                let server_public = PublicKey::from(&server_secret);
                let client_public: PublicKey = serde_json::from_str(&msg.data[0]).unwrap();
                shared_secret = Arc::new(Some(Arc::new(server_secret.diffie_hellman(&client_public))));
                // let key_arr = (*(shared_secret)).unwrap().to_bytes();
                let ref_cell = Option::clone(shared_secret.as_ref());
                let key_arr: [u8; 32] = ref_cell.unwrap().to_bytes();
                println!("client_shared_key {:?}", key_arr);
                key = Arc::new(Some(key_arr.into()));
                let reply = AppMessage{
                    cmd: "new".to_string(),
                    data: vec![serde_json::to_string(&server_public).unwrap()]
                };
                ws_stream.send(Message::text(serde_json::to_string(&reply).unwrap())).await.unwrap();
                // let sent = w.send(Message::text(serde_json::to_string(&reply).unwrap()));
                authenticated = true;
            },
            _ => todo!()
        }
        // let reply = AppMessage{
        //     cmd: "test".to_string(),
        //     data: Vec::new()
        // };
        // w.send(Message::text(serde_json::to_string(&reply).unwrap()));
    }
}