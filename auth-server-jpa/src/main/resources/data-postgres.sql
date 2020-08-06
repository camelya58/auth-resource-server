 INSERT INTO oauth_client_details (
	client_id,client_secret,
	resource_ids,
	scope,
	authorized_grant_types,
	web_server_redirect_uri,authorities,
	access_token_validity,refresh_token_validity,
	additional_information,autoapprove)
	VALUES(
    'USER_CLIENT_APP','$2y$12$qBt9lqRwW3n5Tg8Gf/clvOY.HqPI7xPnIPrmeARN9b1ZBRDsmPEHG',
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
'admin','$2y$12$yEmKyV150Q7GUtDztuzKZuHFVlY2s8mzD7HxgDVDZPji9/udjPF.G',
'william@gmail.com',true,true,true,true),
('user','$2y$12$Qbzvmngmj7rm7LaEUjTo5OA8dHTufdPwiO4umAqFxe/JUURKQndRK',
'john@gmail.com',true,true,true,true);


INSERT INTO role_users (role_id, users_id)
VALUES
(1, 1) /* role_admin assigned to admin user */,
(2, 2) /* role_user assigned to user user */ ;