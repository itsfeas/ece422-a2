use futures::TryStreamExt;
use tokio::net::{TcpListener, TcpStream};
use std::string::String; 
// use std::io::{Write, Read};
use tokio::io::{AsyncWriteExt, AsyncReadExt}; 
use std::error::Error; 
use tokio_tungstenite::{connect_async, client_async_tls, tungstenite::Message};
use futures_util::StreamExt;
use futures_util::SinkExt;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:8080";

    let url = url::Url::parse("ws://127.0.0.1:8080").unwrap();
    println!("URL: {}", url);
    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    let (mut w, mut r) = ws_stream.split();
    
    loop {
        let message = String::from("test message");
        w.send(Message::Text(message.clone())).await;
        println!("Message sent :{:?}", &message);
            
        while let Some(val) = r.next().await {
            let value = val?; 
            if value.is_text() || value.is_binary() {
                println!("Received: {:?}", value); 
            }
        }

    };


    Ok(())
}
