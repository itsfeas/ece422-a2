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
    children VARCHAR[],
    encrypted_name VARCHAR
);

CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    users VARCHAR[],
    g_name VARCHAR UNIQUE
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group_name VARCHAR REFERENCES groups(g_name),
    key VARCHAR,
    salt VARCHAR,
    is_admin BOOLEAN
);

INSERT INTO fnode (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name) VALUES ('home', '/home', NULL, '', '/', true, 7, 7, 7, ARRAY[]::VARCHAR[], '');