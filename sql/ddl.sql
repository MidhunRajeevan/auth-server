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

CREATE TABLE clients (
	id bigserial PRIMARY KEY,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    scope jsonb, 
    authorized_grant_types text default 'client_secret', -- Space-separated list of grant types
    authorities text, -- Space-separated list of authorities
    access_token_validity INT, -- In seconds
    refresh_token_validity INT, -- In seconds
    additional_information jsonb, -- Any additional information
    status text not null default 'pending', -- Client status (e.g., active, inactive, suspended, revoked, pending)
	created_by text not null,
    updated_by text not null,
	created_at timestamptz not null,
	updated_at timestamptz not null
);