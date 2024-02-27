use postgres::{Client, NoTls};

fn main() {
    let mut client = Client::connect("host=localhost user=postgres", NoTls)?;

    println!("Hello, world!");
}
