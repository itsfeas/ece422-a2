
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
struct UserGroupNode {
    id: String,
    name: String,
    has_children: bool,

    //if group
    users: Vec<String>,

    //if user
    is_admin: bool,
    salt: String,
    user_group: String,
}