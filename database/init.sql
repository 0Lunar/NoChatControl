CREATE DATABASE IF NOT EXISTS chat_db;

USE chat_db;

CREATE TABLE credentials(
    id int NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(256) UNIQUE NOT NULL,
    password VARCHAR(256) NOT NULL
);

-- - Password is "test"
INSERT INTO credentials(username, password) VALUES('test', '$2b$12$2xK1J8ekC7oS5PPeVnt6luqcB5J1r2edjFsZV.eHTuBaEj4y89HRa')