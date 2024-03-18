use std::{fmt::format, sync::Arc};

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce
};
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use model::model::FNode;

pub async fn add_file(client: Arc<Mutex<Client>>, file: FNode) -> Result<String, String> {
    let e = client.lock().await.execute("INSERT INTO fnode values (name, path, owner, hash, parent, dir, u, g, o, children) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    &[&file.name, &file.path, &file.owner, &file.hash, &file.parent, &file.dir, &file.u, &file.g, &file.o, &file.children]).await;
    match e {
        Ok(_) => Ok(file.name),
        Err(_) => Err(format!("couldn't create file!")),
    }
}

pub async fn remove_file(client: Arc<Mutex<Client>>, path: String) -> Result<String, String> {
    let e = client.lock().await.execute("DELETE FROM fnode WHERE path=$1",
    &[&path]).await;
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't create file!")),
    }
}

pub fn salt_pass(pass: String) -> Result<String, String> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(b_pass, &salt) {
        Ok(p) => Ok(p.to_string()),
        Err(_) => Err("Error with salting pass".into()),
    }
}

// https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/
pub fn key_gen() -> Result<String, ()> {
    let key = Aes256GcmSiv::generate_key(&mut aes_gcm_siv::aead::OsRng);
    match serde_json::to_string(&key.to_vec()) {
        Ok(s) => Ok(s),
        Err(_) => Err(()),
    }
}

pub async fn auth_user(client: Arc<Mutex<Client>>, user_name: String, pass: String) -> Result<bool, String> {
    let salted = match salt_pass(pass) {
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while authenticating user!")),
    };
    let e = client.lock().await.query_one("SELECT user_name FROM users u WHERE u.user_name=$1 AND u.pass=$2",
    &[&user_name, &salted]).await;
    match e {
        Ok(e) => Ok(true),  //Ok(e.get((0)==user_name)),
        Err(_) => Err(format!("could not query whether user exists!")),
    }
}

//used https://docs.rs/argon2/latest/argon2/
pub async fn create_user(client: Arc<Mutex<Client>>, user_name: String, pass: String, group: Option<String>, is_admin: bool) -> Result<String, String>{
    let salt = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while creating user!")),
    };
    let key = key_gen().expect("could not serialize symmetric key!");
    let e = client.lock().await.execute("INSERT INTO users values (user_name, group, salt, false, key) VALUES ($1, $2, $3, $4, $5)",
    &[&user_name, &group, &salt, &is_admin, &key]).await;
    match e {
        Ok(_) => Ok(user_name),
        Err(_) => Err(format!("couldn't create user!")),
    }
}

pub async fn create_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("INSERT INTO groups values (name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<i64>::new()]).await;
    match e {
        Ok(_) => Ok(group_name),
        Err(_) => Err(format!("couldn't create group!")),
    }
}

pub async fn add_user_to_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("UPDATE groups SET users = ARRAY_APPEND(users, $1) WHERE name=$2",
    &[&user_name, &group_name]).await;
    let e1 = client.lock().await.execute("UPDATE users SET group=$1 WHERE user_name=$2",
    &[&group_name, &user_name]).await;
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

pub async fn remove_user_from_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("UPDATE groups SET users = array_remove(users, $1) WHERE name=$2",
    &[&user_name, &group_name]).await;
    let e1 = client.lock().await.execute("UPDATE users SET group='' WHERE user_name=$2",
    &[&group_name, &user_name]).await;
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to remove user from group!".to_string()),
    }
}

pub async fn get_f_node(client: Arc<Mutex<Client>>, path: String) -> Result<Option<FNode>, String> {
    let e = client.lock().await.query_opt("SELECT id, name, path, owner, hash, key, parent, dir, u, g, o, children FROM fnode WHERE path = $1", &[&path]).await;
    match e {
        Ok(Some(row)) => {
            let fnode = FNode {
                id: row.get(0),
                name: row.get(1),
                path: row.get(2),
                owner: row.get(3),
                hash: row.get(4),
                key: row.get(5),
                parent: row.get(6),
                dir: row.get(7),
                u: row.get(8),
                g: row.get(9),
                o: row.get(10),
                children: row.get(11),
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get fnode!")),
    }
}

pub async fn get_user(client: Arc<Mutex<Client>>, user_name: String) -> Result<Option<String>, String> {
    let e = client.lock().await.query_opt("SELECT user_name FROM users WHERE user_name = $1", &[&user_name]).await;
    match e {
        Ok(Some(_)) => Ok(Some(user_name)),
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get user!")),
    }
}

pub async fn get_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<Option<String>, String> {
    let e = client.lock().await.query_opt("SELECT name FROM groups WHERE name = $1", &[&group_name]).await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get group!")),
    }
}

//////////////////////////////////
///     FILESYSTEM MOVEMENT    ///
//////////////////////////////////


pub trait Traversal {
    fn make_child(&self) -> Result<Self, String> where Self: Sized; 
    fn get_child(&self) -> Result<Self, String> where Self: Sized; 
    fn set_child(&mut self) -> Result<Self, String> where Self: Sized; 
}
