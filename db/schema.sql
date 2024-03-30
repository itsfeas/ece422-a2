CREATE TABLE fnode (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR,
    path VARCHAR,
    owner BIGINT,
    hash VARCHAR,
    parent BIGINT,
    dir BOOLEAN,
    u SMALLINT,
    g SMALLINT,
    o SMALLINT,
    children BIGINT[]
);

CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    users BIGINT[],
    name VARCHAR
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group_id BIGINT REFERENCES groups(id),
    key VARCHAR,
    salt VARCHAR,
    is_admin BOOLEAN
);