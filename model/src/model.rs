
#[derive()]
struct FNode {
    id: String,
    name: String,
    path: String,
    owner: String,
    hash: i128,
    parent: String,
    has_children: bool,
    u: i8,
    g: i8,
    o: i8,
    
    //if directory
    children: Vec<String>,
}

#[derive()]
struct User {
    id: String,
    user_name: String,
    groups: Vec<String>,
    salt: String,
    is_admin: bool
}


#[derive()]
struct Group {
    id: String,
    users: Vec<String>,
    name: String,
}