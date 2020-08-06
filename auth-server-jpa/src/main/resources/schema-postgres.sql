DROP TABLE IF EXISTS oauth_client_details CASCADE;
CREATE TABLE oauth_client_details(
client_id VARCHAR(255) NOT NULL PRIMARY KEY,
client_secret VARCHAR(255) NOT NULL,
resource_ids VARCHAR(255) DEFAULT NULL,
scope VARCHAR(255) DEFAULT NULL,
authorized_grant_types VARCHAR(255) DEFAULT NULL,
web_server_redirect_uri VARCHAR(255) DEFAULT NULL,
authorities VARCHAR(255) DEFAULT NULL,
access_token_validity INT DEFAULT NULL,
refresh_token_validity INT DEFAULT NULL,
additional_information VARCHAR(4096) DEFAULT NULL,
autoapprove VARCHAR(255) DEFAULT NULL);

DROP TABLE IF EXISTS permission CASCADE;
CREATE TABLE permission (
id int PRIMARY KEY,
name VARCHAR(60) UNIQUE);

DROP TABLE IF EXISTS role CASCADE;
CREATE TABLE role
(id int PRIMARY KEY,
name VARCHAR(60) UNIQUE);

DROP TABLE IF EXISTS permission_role CASCADE;
CREATE TABLE permission_role(
permission_id int,
FOREIGN KEY(permission_id) REFERENCES permission(id),
role_id int,
FOREIGN KEY(role_id) REFERENCES role(id));

DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
id int PRIMARY KEY,
username VARCHAR(24) UNIQUE NOT NULL,
password VARCHAR(255) NOT NULL,
email VARCHAR(255) NOT NULL,
enabled boolean NOT NULL,
account_locked boolean NOT NULL,
account_expired boolean NOT NULL,
credentials_expired boolean NOT NULL);

DROP TABLE IF EXISTS role_users CASCADE;
CREATE TABLE role_users (role_id int,FOREIGN KEY(role_id) REFERENCES role(id),
                         users_id int, FOREIGN KEY(users_id) REFERENCES users(id));
