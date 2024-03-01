CREATE TABLE fnode (
    id VARCHAR PRIMARY KEY,
    name VARCHAR,
    path VARCHAR,
    owner VARCHAR,
    hash NUMERIC,
    parent VARCHAR,
    has_children BOOLEAN,
    u SMALLINT,
    g SMALLINT,
    o SMALLINT,
    children TEXT[]
);

CREATE TABLE user_group_node (
    id VARCHAR PRIMARY KEY,
    name VARCHAR,
    has_children BOOLEAN,
    users TEXT[],
    is_admin BOOLEAN,
    salt VARCHAR,
    user_group VARCHAR
);
