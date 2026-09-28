CREATE TABLE blobs (
		id               TEXT PRIMARY KEY,
		owner_token_hash BLOB NOT NULL,    -- SHA-256 of the owner token, never the token
		size             INTEGER NOT NULL,
		created_at       INTEGER NOT NULL  -- Unix seconds
	) STRICT;