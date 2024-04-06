use std::{env, fmt::format, sync::Arc};

use aes_gcm::{Aes256Gcm, Key, KeyInit};
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use argon2::{
    password_hash::{
        Encoding, PasswordHash, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use model::model::{FNode, User};

pub async fn add_file(client: Arc<Mutex<Client>>, file: FNode) -> Result<String, String> {
    let e = client.lock().await.execute("INSERT INTO fnode (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    &[&file.name, &file.path, &file.owner, &file.hash, &file.parent, &file.dir, &file.u, &file.g, &file.o, &file.children, &file.encrypted_name]).await;
    match e {
        Ok(_) => Ok(file.name),
        Err(err) => Err(format!("{}",err)),
    }
}

pub async fn remove_file(client: Arc<Mutex<Client>>, path: String, file_name: String) -> Result<String, String> {
    let e = client.lock().await.execute("DELETE FROM fnode WHERE path=$1 AND name=$2",
    &[&path, &file_name]).await;
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't remove file!")),
    }
}

pub async fn update_hash(client: Arc<Mutex<Client>>, path: String, file_name: String, hash: String) -> Result<String, String>{
    let e = client.lock().await.execute("UPDATE fnode SET hash = $1 WHERE path=$2",
    &[&hash, &path]).await;
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't update hash!")),
    }
}

pub fn salt_pass(pass: String) -> Result<String, String> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(b_pass, &salt) {
        Ok(p) => Ok(p.serialize().as_str().to_string()),
        Err(_) => Err("Error with salting pass".into()),
    }
}

// https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/
pub fn key_gen() -> Result<String, ()> {
    let key = Aes256Gcm::generate_key(&mut aes_gcm_siv::aead::OsRng);
    let u8_32_arr: [u8; 32] = key.into();
    match serde_json::to_string(&u8_32_arr) {
        Ok(s) => Ok(s),
        Err(_) => Err(()),
    }
}

pub async fn auth_user(client: Arc<Mutex<Client>>, user_name: String, pass: String) -> Result<bool, String> {    
    let e = client.lock().await.query_one("SELECT u.salt FROM users u WHERE u.user_name=$1",
    &[&user_name]).await;
    let res = match e {
        Ok(row) => row,
        Err(_) => return Err(format!("could not query whether user exists!")),
    }; 
    let hash: String = res.get("salt");
    let hash_str: PasswordHashString = PasswordHashString::parse(hash.as_str(), Encoding::B64).unwrap();
    let true_hash = hash_str.password_hash();
    match Argon2::default().verify_password(pass.as_bytes(), &true_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

//used https://docs.rs/argon2/latest/argon2/
pub async fn create_user(client: Arc<Mutex<Client>>, user_name: String, pass: String, group: Option<String>, is_admin: bool) -> Result<Key<Aes256Gcm>, String>{
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let salt = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while creating user!")),
    };
    let key = key_gen().expect("could not serialize symmetric key!");
    let e = match group {
        Some(_) => client.lock().await.execute("INSERT INTO users (user_name, group_name, salt, key, is_admin) VALUES ($1, $2, $3, pgp_sym_encrypt($4 ::text, $6 ::text), $5)",
    &[&user_name, &group, &salt, &key, &is_admin, &db_pass]).await,
        None => client.lock().await.execute("INSERT INTO users (user_name, salt, key, is_admin) VALUES ($1, $2, pgp_sym_encrypt($3 ::text, $5 ::text), $4)",
    &[&user_name, &salt, &key, &is_admin, &db_pass]).await,
    };
    match e {
        Ok(_) => Ok(serde_json::from_str::<[u8; 32]>(&key).unwrap().into()),
        Err(e) => Err(format!("couldn't create user! {}", e)),
    }
}

pub async fn create_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("INSERT INTO groups (g_name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<String>::new()]).await;
    match e {
        Ok(_) => Ok(group_name),
        Err(_) => Err(format!("couldn't create group!")),
    }
}

pub async fn add_user_to_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("UPDATE groups SET users = ARRAY_APPEND(users, $1) WHERE g_name=$2",
    &[&user_name, &group_name]).await;
    let e1 = client.lock().await.execute("UPDATE users SET group_name=$1 WHERE user_name=$2",
    &[&group_name, &user_name]).await;
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

pub async fn remove_user_from_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("UPDATE groups SET users = array_remove(users, $1) WHERE g_name=$2",
    &[&user_name, &group_name]).await;
    let e1 = client.lock().await.execute("UPDATE users SET group='' WHERE user_name=$2",
    &[&group_name, &user_name]).await;
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to remove user from group!".to_string()),
    }
}

pub async fn add_file_to_parent(client: Arc<Mutex<Client>>, parent_path: String, new_f_node_name: String) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET children = ARRAY_APPEND(children, $1) WHERE path=$2",
    &[&new_f_node_name, &parent_path]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

pub async fn remove_file_from_parent(client: Arc<Mutex<Client>>, parent_path: String, f_node_name: String) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET children = ARRAY_REMOVE(children, $1) WHERE path=$2",
    &[&f_node_name, &parent_path]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

pub async fn get_f_node(client: Arc<Mutex<Client>>, path: String) -> Result<Option<FNode>, String> {
    let e = client.lock().await.query_opt("SELECT * FROM fnode WHERE path = $1", &[&path]).await;
    match e {
        Ok(Some(row)) => {
            let fnode = FNode {
                id: row.get(0),
                name: row.get(1),
                path: row.get(2),
                owner: row.try_get(3).unwrap_or("".to_string()),
                hash: row.get(4),
                parent: row.get(5),
                dir: row.get(6),
                u: row.get(7),
                g: row.get(8),
                o: row.get(9),
                children: row.get(10),
                encrypted_name: row.get(11),
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get fnode!")),
    }
}

pub async fn change_file_perms(client: Arc<Mutex<Client>>, file_path: String, u: i16, g: i16, o: i16) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET u=$2, g=$3, o=$4 WHERE path=$1",
    &[&file_path, &u, &g, &o]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update file permissions!".to_string()),
    }
}

pub async fn update_path(client: Arc<Mutex<Client>>, file_path: String, new_file_path: String) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET path = regexp_replace(path, $1, $2, 'g') WHERE path ~ $3",
        &[&format!("^{}", file_path), &new_file_path, &format!("^{}", file_path)]
    ).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update path!".to_string()),
    }
}

pub async fn update_fnode_name_if_path_is_already_updated(client: Arc<Mutex<Client>>, path: String, new_name: String) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET name = $2 WHERE path = $1",
    &[&path, &new_name]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update f_node name!".to_string()),
    }
}

pub async fn update_fnode_enc_name(client: Arc<Mutex<Client>>, path: String, new_enc_name: String) -> Result<(), String>{
    let e = client.lock().await.execute("UPDATE fnode SET encrypted_name = $2 WHERE path = $1",
    &[&path, &new_enc_name]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update f_node name!".to_string()),
    }
}

pub async fn get_user(client: Arc<Mutex<Client>>, user_name: String) -> Result<Option<User>, String> {
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let e = if user_name == "admin" {
        client.lock().await.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, 'DOES_NOT_MATTER' ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name]).await
    } else {
        // does not matter if admin enryption key is available since they don't have file interactions
        client.lock().await.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, $2 ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name, &db_pass]).await
    };
    match e {
        Ok(Some(row)) => Ok(Some(User{
            id: row.get("id"),
            user_name: row.get("user_name"),
            group_name: row.try_get("group_name").unwrap_or(None),
            key: row.get("key"),
            salt: row.get("salt"),
            is_admin: row.get("is_admin"),
        })),
        Ok(None) => Ok(None),
        Err(err) => Err(format!("failed to get user! {}", err)),
    }
}

pub async fn get_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<Option<String>, String> {
    let e = client.lock().await.query_opt("SELECT g_name FROM groups WHERE g_name = $1", &[&group_name]).await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get group!")),
    }
}

// //////////////////////////////////
// ///     FILESYSTEM MOVEMENT    ///
// //////////////////////////////////


// pub trait Traversal {
//     fn make_child(&self) -> Result<Self, String> where Self: Sized; 
//     fn get_child(&self) -> Result<Self, String> where Self: Sized; 
//     fn set_child(&mut self) -> Result<Self, String> where Self: Sized; 
// }
