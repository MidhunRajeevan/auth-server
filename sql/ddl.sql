CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    username CITEXT NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username CITEXT NOT NULL,
    authority CITEXT NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username),
    CONSTRAINT unique_authority_per_user UNIQUE (username, authority)
);

CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);

insert into users values('midhun', '{noop}1234',TRUE);
insert into authorities values('midhun', 'admin');

