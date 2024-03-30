CREATE TABLE if not exists fnode  (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR,
    path VARCHAR,
    owner VARCHAR,
    hash VARCHAR,
    parent VARCHAR,
    dir BOOLEAN,
    u SMALLINT,
    g SMALLINT,
    o SMALLINT,
    children VARCHAR[]
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

INSERT INTO fnode (name, path, owner, hash, parent, dir, u, g, o, children) VALUES ('home', '/', NULL, '', '/', true, 7, 7, 7, ARRAY[]::BIGINT[]);