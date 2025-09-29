CREATE DATABASE IF NOT EXISTS chat_db;

USE chat_db;

CREATE TABLE users(
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(60),
    email VARCHAR(120),
    banned BOOLEAN DEFAULT false
);


CREATE TABLE credentials(
    CredID INT AUTO_INCREMENT PRIMARY KEY,
    user INT,
    password VARCHAR(60),    -- - Bcrypt

    FOREIGN KEY (user) REFERENCES users(UserID)
);


CREATE TABLE groups(
    GroupID INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT
);


CREATE TABLE group_users(
    GroupID INT,
    UserID INT,

    FOREIGN KEY (GroupID) REFERENCES groups(GroupID),
    FOREIGN KEY (UserID) REFERENCES users(UserID)
);


CREATE TABLE group_banned(
    GroupID INT,
    UserID INT,

    FOREIGN KEY (GroupID) REFERENCES groups(GroupID),
    FOREIGN KEY (UserID) REFERENCES users(UserID)
);


CREATE TABLE friends(
    UserID INT,
    FriendID INT,

    FOREIGN KEY (UserID) REFERENCES users(UserID),
    FOREIGN KEY (FriendID) REFERENCES users(UserID)
);


CREATE TABLE group_invite(
    InviteID INT AUTO_INCREMENT,
    group INT,
    token VARCHAR(20),
    expire DATETIME,

    FOREIGN KEY (group) REFERENCES groups(GroupID)
);