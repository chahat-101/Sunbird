ALTER TABLE blobs ADD COLUMN uploader_id TEXT;
	 CREATE INDEX blobs_uploader ON blobs (uploader_id, expires_at);
	 CREATE TABLE uploads (
		uploader_id TEXT NOT NULL,
		size        INTEGER NOT NULL,
		created_at  INTEGER NOT NULL  -- Unix seconds
	 ) STRICT;
	 CREATE INDEX uploads_uploader ON uploads (uploader_id, created_at);