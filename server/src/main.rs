use std::io::Error;
use futures_util::{future, StreamExt, TryStreamExt};
use tokio::net::{TcpListener, TcpStream};
use postgres::{Client, NoTls};

#[path = "./dao/dao.rs"]
mod dao;

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

    let (w, r) = ws_stream.split();
    r.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
        .forward(w)
        .await
        .expect("failed")
}