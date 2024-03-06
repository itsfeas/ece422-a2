use std::fmt::format;

use postgres::{Client, NoTls};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use model::model::FNode;

fn add_file(client: &mut Client, file: FNode) -> Result<String, String> {
    let e = client.execute("INSERT INTO fnode values (name, path, owner, hash, parent, dir, u, g, o, children) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    &[&file.name, &file.path, &file.owner, &file.hash, &file.parent, &file.dir, &file.u, &file.g, &file.o, &file.children]);
    match e {
        Ok(_) => Ok(file.name),
        Err(_) => Err(format!("couldn't create file!")),
    }
}

fn remove_file(client: &mut Client, path: String) -> Result<String, String> {
    let e = client.execute("DELETE FROM fnode WHERE path=$1",
    &[&path]);
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't create file!")),
    }
}

pub fn salt_pass(pass: String) -> Result<String, String> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(b_pass, &salt) {
        Ok(p) => Ok(p.to_string()),
        Err(_) => Err("Error".into()),
    }
}

pub fn auth_user(client: &mut Client, user_name: String, pass: String) -> Result<bool, String> {
    let salted = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while authenticating user!")),
    };
    let e = client.query_one("SELECT user_name FROM users u WHERE u.user_name=$1 AND u.pass=$2",
    &[&user_name, &salted]);
    match e {
        Ok(e) => Ok(true),  //Ok(e.get((0)==user_name)),
        Err(_) => Err(format!("could not query whether user exists!")),
    }
}

//used https://docs.rs/argon2/latest/argon2/
pub fn create_user(client: &mut Client, user_name: String, pass: String, group: String, is_admin: bool) -> Result<String, String>{
    let salt = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while creating user!")),
    };
    let e = client.execute("INSERT INTO users values (user_name, group, salt, false) VALUES ($1, $2, $3, $4)",
    &[&user_name, &group, &salt, &is_admin]);
    match e {
        Ok(_) => Ok(user_name),
        Err(_) => Err(format!("couldn't create user!")),
    }
}

pub fn create_group(client: &mut Client, group_name: String) -> Result<String, String>{
    let e = client.execute("INSERT INTO groups values (name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<i64>::new()]);
    match e {
        Ok(_) => Ok(group_name),
        Err(_) => Err(format!("couldn't create group!")),
    }
}

pub fn add_user_to_group(client: &mut Client, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.execute("UPDATE groups SET users = ARRAY_APPEND(users, $1) WHERE name=$2",
    &[&user_name, &group_name]);
    let e1 = client.execute("UPDATE users SET group=$1 WHERE user_name=$2",
    &[&group_name, &user_name]);
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

pub fn remove_user_from_group(client: &mut Client, user_name: String, group_name: String) -> Result<String, String>{
    let e = client.execute("UPDATE groups SET users = array_remove(users, $1) WHERE name=$2",
    &[&user_name, &group_name]);
    let e1 = client.execute("UPDATE users SET group='' WHERE user_name=$2",
    &[&group_name, &user_name]);
    match (e, e1) {
        (Ok(_), Ok(_)) => Ok(group_name),
        _ => Err("Failed to remove user from group!".to_string()),
    }
}

pub fn get_f_node(client: &mut Client, path: String) -> Result<Option<FNode>, String> {
    let e = client.query_opt("SELECT id, name, path, owner, hash, parent, dir, u, g, o, children FROM fnode WHERE path = $1", &[&path]);
    match e {
        Ok(Some(row)) => {
            let fnode = FNode {
                id: row.get(0),
                name: row.get(1),
                path: row.get(2),
                owner: row.get(3),
                hash: row.get(4),
                parent: row.get(5),
                dir: row.get(6),
                u: row.get(7),
                g: row.get(8),
                o: row.get(9),
                children: row.get(10),
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get fnode!")),
    }
}

pub fn get_user(client: &mut Client, user_name: String) -> Result<Option<String>, String> {
    let e = client.query_opt("SELECT user_name FROM users WHERE user_name = $1", &[&user_name]);
    match e {
        Ok(Some(_)) => Ok(Some(user_name)),
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get user!")),
    }
}

pub fn get_group(client: &mut Client, group_name: String) -> Result<Option<String>, String> {
    let e = client.query_opt("SELECT name FROM groups WHERE name = $1", &[&group_name]);
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
