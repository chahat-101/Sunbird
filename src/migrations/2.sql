ALTER TABLE blobs ADD COLUMN expires_at    INTEGER NOT NULL DEFAULT 0; -- Unix seconds; expired once the clock reaches it
	 ALTER TABLE blobs ADD COLUMN max_downloads INTEGER NOT NULL DEFAULT 0; -- 0 means no download limit, not zero downloads
	 ALTER TABLE blobs ADD COLUMN downloads     INTEGER NOT NULL DEFAULT 0; -- claims not refunded, in flight included
	 ALTER TABLE blobs ADD COLUMN in_flight     INTEGER NOT NULL DEFAULT 0; -- claims whose transfer has not ended
	 ALTER TABLE blobs ADD COLUMN deleting      INTEGER NOT NULL DEFAULT 0; -- 1: never served again; blob, then row, go
	 UPDATE blobs SET expires_at = created_at + 86400, max_downloads = 1;
	 CREATE INDEX blobs_expires_at ON blobs (expires_at);