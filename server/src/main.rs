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


// https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
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
    
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(v) => v,
        Err(e) => panic!("error during websocket handshake!: {}", e),
    };
    println!("New WebSocket connection: {}", addr);

    let mut shared_secret: Arc<Option<SharedSecret>> = Arc::new(None);

    let (mut w, r) = ws_stream.split();
    let mut authenticated = false;
    let stream = r.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
        .map(|msg| msg.unwrap())
        .map(|msg| msg.to_string())
        .for_each(|msg_serialized| {
            let msg: AppMessage = match authenticated {
                true => todo!(),
                false => serde_json::from_str(&msg_serialized).unwrap(),
            };
            match msg.cmd.as_str() {
                "new" => {
                    let server_secret = EphemeralSecret::random_from_rng(OsRng);
                    let server_public = PublicKey::from(&server_secret);
                    let client_public: PublicKey = serde_json::from_str(&msg.data[0]).unwrap();
                    shared_secret = Arc::new(Some(server_secret.diffie_hellman(&client_public)));
                    let reply = AppMessage{
                        cmd: "new".to_string(),
                        data: vec![serde_json::to_string(&server_public).unwrap()]
                    };
                    w.send(Message::text(serde_json::to_string(&reply).unwrap()));
                    authenticated = true;
                },
                _ => todo!()
            }
            // let reply = AppMessage{
            //     cmd: "test".to_string(),
            //     data: Vec::new()
            // };
            // w.send(Message::text(serde_json::to_string(&reply).unwrap()));
            future::ready(())
        });
    stream.await
}