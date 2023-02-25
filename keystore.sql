PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE LogFiles   (id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                         Name        TEXT    NOT NULL,
			 Date        TEXT    DEFAULT 0 NOT NULL,
			 Size        INTEGER DEFAULT 0, 
                         UNIQUE(id));
CREATE TABLE MACProvFrames (id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                            CanId       TEXT,
			    Frame       TEXT,
			    FOREIGN KEY (LogFileId) REFERENCES LogFiles (id), 
                            UNIQUE(id));
CREATE TABLE SHEArgsPackets (id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                             FrameId     TEXT,
			     M1          TEXT, 
			     M2          TEXT, 
			     M3          TEXT, 
			     M4          TEXT, 
			     M5          TEXT,
			     FOREIGN KEY (MACProvFrameId) REFERENCES MACProvFrames (id), 
                             UNIQUE(id));
CREATE TABLE MACKeys (id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                      MacKey       TEXT,
                      MasterMacKey TEXT,
                      FOREIGN KEY (SHEArgsId) REFERENCES SHEArgsPackets (id),
                      UNIQUE(id));
COMMIT;
