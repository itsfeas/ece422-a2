use std::io::Error;
use futures_util::{future, StreamExt, TryStreamExt};
use tokio::net::{TcpListener, TcpStream};

use postgres::{Client, NoTls};

// https://github.com/snapview/tokio-tungstenite/blob/master/examples/echo-server.rs
#[tokio::main]
async fn main() -> Result<(), Error> {
    // let mut client = Client::connect("host=localhost user=postgres", NoTls)?;
    // println!("Hello, world!");
    let addr = "127.0.0.1:8080".to_string();
    // let sock = TcpListener
    let sock = TcpListener::bind(&addr).await;
    let listener = sock.expect("failed to bind");
    print!("listening on: {}", addr);
    while let (Ok((stream, _))) = listener.accept().await {
        
    }
    Ok(())
}

async fn accept_connection(stream: TcpStream) {
    let addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => panic!("could not find peer address!")
    };
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(v) => v,
        Err(_) => panic!("error during websocket handshake!"),
    };
    print!("connected to: {}", addr);
    let (w, r) = ws_stream.split();
    let s = r.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
        .forward(w)
        .await
        .expect("failed");
}