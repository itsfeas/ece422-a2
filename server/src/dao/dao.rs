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
        Err(_) => Err(()),
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
        Ok(e) => Ok(e.get(0)==user_name),
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
    let e = client.execute("INSERT INTO groups values (name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<i64>::new()]);
    match e {
        Ok(_) => Ok(group_name),
        Err(_) => Err(()),
    }
}