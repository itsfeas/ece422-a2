CREATE TABLE fnode (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR,
    path VARCHAR,
    owner BIGINT,
    hash VARCHAR,
    parent BIGINT,
    has_children BOOLEAN,
    u SMALLINT,
    g SMALLINT,
    o SMALLINT,
    children BIGINT[]
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group BIGINT FOREIGN KEY groups.id,
    salt VARCHAR,
    is_admin BOOLEAN
);

CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    users BIGINT[] FOREIGN KEY users.id,
    name VARCHAR
);
