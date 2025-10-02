CREATE DATABASE IF NOT EXISTS chat_db;

USE chat_db;

CREATE TABLE users(
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(60),
    email VARCHAR(120),
    banned BOOLEAN DEFAULT false,
    admin BOOLEAN DEFAULT false
);


CREATE TABLE credentials(
    CredID INT AUTO_INCREMENT PRIMARY KEY,
    user INT,
    password VARCHAR(60),    -- - Bcrypt

    FOREIGN KEY (user) REFERENCES users(UserID)
);


CREATE TABLE tokens(
    TokenID INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(32),
    user INT,

    FOREIGN KEY (user) REFERENCES users(UserID)
);