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
Add data to application.properties file.
```properties
server.port=9020

spring.datasource.url=jdbc:postgresql://localhost:5432/oauth
spring.datasource.username=root
spring.datasource.password=root
spring.datasource.driverClassName=org.postgresql.Driver
spring.datasource.platform=postgres
spring.jpa.database=POSTGRESQL
spring.datasource.initialization-mode=always
# JPA config
spring.jpa.generate-ddl=true
spring.jpa.hibernate.ddl-auto=update

check-user-scopes=true
```

## Step 4
Create models.

First of all create basic - BaseIdEntity class for all entities with id generation.
```java
@MappedSuperclass
public class BaseIdEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected long id;
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

[Source](https://www.youtube.com/watch?v=wxebTn_a930)