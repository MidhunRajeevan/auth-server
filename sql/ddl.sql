CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
	id bigserial PRIMARY KEY,
    username text NOT NULL,
    password text NOT NULL,
    role text NOT NULL,
    status text not null default 'pending',
	created_by text not null,
    updated_by text not null,
	created_at timestamptz not null,
	updated_at timestamptz not null
);