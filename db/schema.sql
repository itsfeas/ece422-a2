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
INSERT INTO users (id, user_name, key, salt, is_admin) VALUES (0, 'admin', '[100,174,57,154,61,13,222,17,137,223,246,116,105,118,187,175,76,172,152,68,198,97,243,6,11,97,247,132,212,78,107,171]', '$argon2id$v=19$m=19456,t=2,p=1$AD093dKUNbvmWSKukuWzHA$6VzZV0P460A8l0ATWZ0zFAH/ao4zX3o9zLiLRHr1ZbU', true);