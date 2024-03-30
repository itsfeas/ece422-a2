CREATE TABLE if not exists fnode  (
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

CREATE TABLE if not exists groups(
    id BIGSERIAL PRIMARY KEY,
    users BIGINT[],
    name VARCHAR
);
CREATE TABLE if not exists users (
    id BIGSERIAL PRIMARY KEY,
    user_name VARCHAR,
    group_id BIGINT references groups,
    key VARCHAR,
    salt VARCHAR,
    is_admin BOOLEAN
);