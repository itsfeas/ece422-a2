use tungstenite::{connect, Message};

fn main() {
    let server_addr = "ws://127.0.0.1:8080";
    let (mut socket, _) = connect(server_addr).expect("Can't connect");
    println!("connected!");
    
    for i in 0..1000 {
        let message = Message::Text(format!("test message {}", i));
        socket.write(message).expect("Error writing");
        let _ = socket.flush();
        let resp = socket.read().expect("Error reading"); 
    
        println!("{}", resp.to_text().unwrap()); 
    }
    socket.close(None).unwrap();
}
