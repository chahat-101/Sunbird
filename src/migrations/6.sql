CREATE TABLE google_members (
		sub_sha256   BLOB PRIMARY KEY,
		member_id    TEXT NOT NULL UNIQUE,
		token_sha256 BLOB NOT NULL UNIQUE,
		banned       INTEGER NOT NULL DEFAULT 0
	 ) STRICT;
