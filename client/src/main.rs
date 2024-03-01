use std::net::{TcpListener, TcpStream};
use std::string::String; 
use std::io::{Write, Read};

fn main() {
    let server_addr = "127.0.0.1:2222";
    let mut stream = TcpStream::connect(server_addr).expect("TCP connection failed"); 

    while true {
        let message = String::from("test message");
        let mut buffer = Vec::new(); 
        stream.write(&message.as_bytes()).expect("Error writing");
        stream.read(&mut buffer).expect("Error reading"); 

        println!("{}", String::from_utf8(buffer.clone()).unwrap()); 
    }
}
