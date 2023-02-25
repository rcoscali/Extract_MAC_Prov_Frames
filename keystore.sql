PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE LogFiles   (id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                         Name            TEXT    NOT NULL,
                         LogDate         TEXT    DEFAULT 0 NOT NULL,
                         ImportDate      TEXT    DEFAULT 0 NOT NULL,
                         UUID            TEXT    DEFAULT 0 NOT NULL,
                         Size            INTEGER DEFAULT 0,
                         Content         BLOB,
                         FramesExtracted BOOLEAN DEFAULT 0 NOT NULL,
                         UNIQUE(id));
CREATE TABLE MACProvFrames (id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                            LogFileId       INTEGER,
                            CanId           TEXT,
                            Frame           TEXT,
                            SHECmdExtracted BOOLEAN DEFAULT 0 NOT NULL,
                            FOREIGN KEY (LogFileId) REFERENCES LogFiles (id),
                            UNIQUE(id));
CREATE TABLE SHEArgsPackets (id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                             MACProvFrameId INTEGER,
                             M1             TEXT,
                             M2             TEXT,
                             M3             TEXT,
                             M4             TEXT,
                             M5             TEXT,
                             KeysExtracted  BOOLEAN DEFAULT 0 NOT NULL,
                             FOREIGN KEY (MACProvFrameId) REFERENCES MACProvFrames (id),
                             UNIQUE(id));
CREATE TABLE MACKeys        (id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                             SHEPacketsId TEXT,
                             MacKey       TEXT,
                             MasterMaxKey TEXT,
                             FOREIGN KEY (SHEPacketsId) REFERENCES MACProvFrames (id),
                             UNIQUE(id));
DELETE FROM sqlite_sequence;
COMMIT;
