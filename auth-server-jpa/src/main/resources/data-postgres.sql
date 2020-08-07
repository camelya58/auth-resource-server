 INSERT INTO oauth_client_details (
	client_id,client_secret,
	resource_ids,
	scope,
	authorized_grant_types,
	web_server_redirect_uri,authorities,
	access_token_validity,refresh_token_validity,
	additional_information,autoapprove)
	VALUES(
    'USER_CLIENT_APP','{bcrypt}$2a$10$EOs8VROb14e7ZnydvXECA.4LoIhPOoFHKvVF/iBZ/ker17Eocz4Vi',
	'USER_CLIENT_RESOURCE,USER_ADMIN_RESOURCE',
	'role_admin,role_user',
	'authorization_code,password,refresh_token,implicit',
	NULL,NULL,
	900,3600,
	'{}',NULL);

INSERT INTO permission (name) VALUES
('can_create_user'),
('can_update_user'),
('can_read_user'),
('can_delete_user');

INSERT INTO role (name) VALUES
('role_admin'),('role_user');

INSERT INTO permission_role (permission_id, role_id) VALUES
(1,1), /* can_create_user assigned to role_admin */
(2,1), /* can_update_user assigned to role_admin */
(3,1), /* can_read_user assigned to role_admin */
(4,1), /* can_delete_user assigned to role_admin */
(3,2);  /* can_read_user assigned to role_user */

INSERT INTO users (
username,password,
email,enabled,account_locked, account_expired,credentials_expired) VALUES (
'admin','{bcrypt}$2a$10$EOs8VROb14e7ZnydvXECA.4LoIhPOoFHKvVF/iBZ/ker17Eocz4Vi',
'william@gmail.com',true,true, true, true),
('user','{bcrypt}$2a$10$EOs8VROb14e7ZnydvXECA.4LoIhPOoFHKvVF/iBZ/ker17Eocz4Vi',
'john@gmail.com',true,true, true, true);


INSERT INTO role_users (role_id, users_id)
VALUES
(1, 1) /* role_admin assigned to admin user */,
(2, 2) /* role_user assigned to user user */ ;