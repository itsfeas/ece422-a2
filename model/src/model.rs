use serde::{Deserialize, Serialize};

#[derive()]
pub struct FNode {
    pub id: String,
    pub name: String,
    pub path: String,
    pub owner: String,
    pub hash: String,
    pub parent: String,
    pub dir: bool,
    pub u: i8,
    pub g: i8,
    pub o: i8,
    
    //if directory
    pub children: Vec<String>,
}

#[derive()]
pub struct User {
    pub id: String,
    pub user_name: String,
    pub group: String,
    pub salt: String,
    pub is_admin: bool
}


#[derive()]
pub struct Group {
    pub id: String,
    pub users: Vec<String>,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Cmd {
    Cat,
    Cd,
    Echo,
    Login,
    Ls,
    Mkdir,
    Mv,
    NewConnection,
    NewUser,
    Failure,
    Pwd,
    Touch,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppMessage {
    pub cmd: Cmd,
    pub data: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug)] 
pub struct Path {
    pub path: Vec<(bool, String)>
}
