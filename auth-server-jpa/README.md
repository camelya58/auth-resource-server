# auth-server-jpa
Simple project with Spring Security using JWT as authorization server.

Stack: Spring Cloud Security, JWT, Spring Cloud Oath2, JPA, PostgreSQL.

## Step 1
Create spring boot project using Spring Initializr and add spring boot starter web, spring boot starter cloud security,
spring data jpa, spring cloud starter oauth2, postgresql.

## Step 2
Generate a KeyStore file with following command:
```
keytool -genkeypair -alias jwt -keyalg RSA -keypass password -keystore jwt.jks -storepass password
```
The command will generate a file called jwt.jks which contains the Public and Private Keys.

It's recommended to migrate PKCS12.
```
keytool -importkeystore -srckeystore jwt.jks -destkeystore jwt.jks -deststoretype pkcs12
```
Export the public key.
``` 
keytool -list -rfc --keystore jwt.jks | openssl x509 -inform pem -pubkey
```

Copy jwt.jks file to your resources folder.

Copy from (including) -----BEGIN PUBLIC KEY----- to (including) -----END PUBLIC KEY-----
and save it to a file.

## Step 3
Add data to application.yml file.
```yml
server:
  port: 9020

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/oauth
    username: root
    password: root
    driverClassName: org.postgresql.Driver
    platform: postgres
    initialization-mode: never
# JPA config
  jpa:
    database: POSTGRESQL
    hibernate.ddl-auto: validate

check-user-scopes: true
```

## Step 4
Create models.

First of all create basic - BaseIdEntity class for all entities with id generation.
```java
@MappedSuperclass
public class BaseIdEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected int id;
}
``` 
Create class Permission with a field describing authorities.
```java
@Entity(name = "permission")
public class Permission extends BaseIdEntity {
    private String name;

    // Getters and Setters
}
```

Create class Role with list of authorities.
```java
@Entity(name = "role")
public class Role extends  BaseIdEntity {

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "permission_role", joinColumns = {
            @JoinColumn(name = "role_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "permission_id", referencedColumnName = "id")})
    private List<Permission> permissions;

    private String name;
    // Getters and Setters
}
```

Create class User which implements UserDetails and overrides all methods.
```java
@Entity(name = "users")
public class User extends BaseIdEntity implements UserDetails {

    private static final long serialVersionUID = 1L;
    private String email;
    private String username;
    private String password;
    private boolean enabled;

    @Column(name = "account_locked")
    private boolean accountNonLocked;

    @Column(name = "account_expired")
    private boolean accountNonExpired;

    @Column(name = "credentials_expired")
    private boolean credentialsNonExpired;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "role_user", joinColumns = {
            @JoinColumn(name = "user_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id", referencedColumnName = "id")})
    private List<Role> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new HashSet<>();

        roles.forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
            role.getPermissions().forEach(permission -> {
                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            });
        });
        return null;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public String getEmail() {
            return email;
    }
    // Equals and Hashcode

}
```

## Step 5
Create an interface UserRepository to connects with PostgreSQL.
```java
@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {
    
    User findUserByUsername(String username);
}
```

## Step 6
Create class CustomUserDetailsService which implements UserDetailsService and overrides all methods.
```java
@Service(value = "userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);

        if (user == null)
            throw new BadCredentialsException("Bad Credentials");
        new AccountStatusUserDetailsChecker().check(user);

        return user;
    }
}
```
We check our user using class AccountStatusUserDetailsChecker.

## Step 7
Create class WebSecurityConfig which contains web security configurations.
```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(encoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().exceptionHandling()
                .authenticationEntryPoint((httpServletRequest, httpServletResponse, authException) ->
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and().authorizeRequests().antMatchers("/**")
                .authenticated().and().httpBasic();
    }
}
```

## Step 8
Create a class CustomTokenEnhancer which enhances access token and adds additional information about user like email.
```java
public class CustomTokenEnhancer extends JwtAccessTokenConverter {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        User user = (User) authentication.getPrincipal();

        Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());
        info.put("email", user.getEmail());

        DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);
        customAccessToken.setAdditionalInformation(info);

        return super.enhance(customAccessToken, authentication);
    }
}
```

## Step 9
Create a class CustomOauth2RequestFactory represents a filter which creates a token requests before any user requests.
```java
public class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    UserDetailsService userDetailsService;

    public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService) {
        super(clientDetailsService);
    }

    @Override
    public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {
        if (requestParameters.get("grant_type").equals("refresh_token")) {
            OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(
                    tokenStore.readRefreshToken(requestParameters.get("refresh_token")));
            SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getName(), null,
                            userDetailsService.loadUserByUsername(authentication.getName()).getAuthorities()));
        }

        return super.createTokenRequest(requestParameters, authenticatedClient);
    }
}
```
## Step 10 
Create class AuthorizationServerConfig which contains configurations for Authorization server.

The annotation @EnableAuthorizationServer allows our application act as Authorization server.
```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${check-user-scopes}")
    private Boolean checkUserScopes;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Bean
    public OAuth2RequestFactory requestFactory() {
        CustomOauth2RequestFactory requestFactory = new CustomOauth2RequestFactory(clientDetailsService);
        requestFactory.setCheckUserScopes(true);
        return requestFactory;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new CustomTokenEnhancer();
        converter.setKeyPair(
                new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"),
                        "password".toCharArray()).getKeyPair("jwt"));
        return converter;

    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }

    @Bean
    public TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter() {
        return new TokenEndpointAuthenticationFilter(authenticationManager, requestFactory());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtAccessTokenConverter())
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
        if (checkUserScopes)
            endpoints.requestFactory(requestFactory());
    }
}
```

## Step 11
Create the tables using scheme-postgres.sql.
```sql
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
```

Fill the tables using data-postgres.sql.
```sql
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
'william@gmail.com',true,true,true,true),
('user','{bcrypt}$2a$10$EOs8VROb14e7ZnydvXECA.4LoIhPOoFHKvVF/iBZ/ker17Eocz4Vi',
'john@gmail.com',true,true,true,true);


INSERT INTO role_users (role_id, users_id)
VALUES
(1, 1) /* role_admin assigned to admin user */,
(2, 2) /* role_user assigned to user user */ ;
```

## Step 12
Run the project at http://localhost:9020/oauth/token using Postman.

Fill "Authorization":
- Type - Basic Auth.
- Username - USER_CLIENT_APP.
- Password - password.

Fill "Body":
- grant_type - password.
- username - admin.
- password - password.

[Source](https://www.youtube.com/watch?v=wxebTn_a930)
