PRAGMA foreign_keys = ON;

CREATE TABLE roles ( /* all users can view archived posts */
    name TEXT PRIMARY KEY NOT NULL,
    post BOOLEAN NOT NULL CHECK (post IN (0, 1)), /* post and correct your own post. can make and view their own drafts */
    correct BOOLEAN NOT NULL CHECK (correct IN (0, 1)), /* correct another person's post */
    archive BOOLEAN NOT NULL CHECK (archive IN (0, 1)), /* archive another person's post */
    "delete" BOOLEAN NOT NULL CHECK ("delete" IN (0, 1)), /* permanently delete another person's post */
    admin BOOLEAN NOT NULL CHECK (admin IN (0, 1)) /* TRUE = change permissions of everyone and add users, FALSE = change no permissions */
);

CREATE TABLE users (
    name TEXT PRIMARY KEY NOT NULL,
    created TEXT NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    FOREIGN KEY (role) REFERENCES roles (name)
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    published TEXT NOT NULL,
    title TEXT NOT NULL,
    subtitle TEXT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    corrections TEXT,
    archived BOOLEAN NOT NULL CHECK (archived IN (0, 1)), /* TRUE = archived, FALSE = published */
    category TEXT NOT NULL,
    FOREIGN KEY (author) REFERENCES users (name)
);

INSERT INTO roles (name, post, correct, archive, "delete", admin)
    VALUES ("none", 0, 0, 0, 0, 0);
INSERT INTO roles (name, post, correct, archive, "delete", admin)
    VALUES ("poster", 1, 0, 0, 0, 0);
INSERT INTO roles (name, post, correct, archive, "delete", admin)
    VALUES ("editor", 1, 1, 1, 0, 0);
INSERT INTO roles (name, post, correct, archive, "delete", admin)
    VALUES ("admin", 1, 1, 1, 1, 1);
