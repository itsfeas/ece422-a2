CREATE TABLE fnode (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR,
    path VARCHAR,
    owner BIGSERIAL FOREIGN KEY user_group_node.id,
    hash NUMERIC,
    parent BIGSERIAL,
    has_children BOOLEAN,
    u SMALLINT,
    g SMALLINT,
    o SMALLINT,
    children BIGSERIAL[]
);

CREATE TABLE user_group_node (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR,
    has_children BOOLEAN,
    users BIGSERIAL[],
    is_admin BOOLEAN,
    salt VARCHAR,
    user_group BIGSERIAL
);
