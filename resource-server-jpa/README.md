# resource-server-jpa
Simple project with Spring Security using JWT as resource server.

Stack: Spring Cloud Security, JWT, Spring Oath2.

## Step 1
Create spring boot project using Spring Initializr and add spring boot starter web, spring boot starter cloud security,
spring security oauth2, spring security oauth2 autoconfigure.

## Step 2
Create application.yml and add public key like in authorization server.
```yml
server:
  port: 9021

security:
  oauth2:
     resource:
        jwt:
          key-value: 
            -----BEGIN PUBLIC KEY-----
            some key
            -----END PUBLIC KEY-----
```

## Step 3
Create a model - CustomPrincipal.
```java
public class CustomPrincipal implements Serializable {

    private static final long serialVersionUID = 1L;
    private String username;
    private String email;

    public CustomPrincipal() {
    }

    public CustomPrincipal(String username, String email) {
        this.username = username;
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
```

## Step 4
Create a simple REST-controller with endpoints for authorized (only has role "admin" or any role) and unauthorized users.

We also will be able to get user name and email from SecurityContextHolder.
```java
@RestController
public class ResourceController {

    @GetMapping("/admins")
    @PreAuthorize("hasAuthority('role_admin')")
    public String context() {
        CustomPrincipal principal = (CustomPrincipal) SecurityContextHolder
                .getContext().getAuthentication().getPrincipal();
        return principal.getUsername() + " " + principal.getEmail();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('role_admin','role_user')")
    public String secured(CustomPrincipal principal) {
        return principal.getUsername() + " " + principal.getEmail();
    }

    @GetMapping("/common")
    public String general() {
        return "common api success";
    }
}
```

## Step 5
Create configuration class with resource server settings.
```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    public TokenStore tokenStore;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("USER_ADMIN_RESOURCE").tokenStore(tokenStore);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().permitAll()
                .and().cors().disable().csrf().disable().httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(
                        (httpServletRequest, httpServletResponse, authExc) ->
                                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .accessDeniedHandler((httpServletRequest, httpServletResponse, e) ->
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED));
    }
}
```
We set resourceId the same as our client has (see in authorization server) and token store(it will use our public key).

As well as we set exception handling for any request.

## Step 6
Create another configuration class with web settings. We put our CustomPrincipal in the SecurityContextHolder.
```java
@Configuration
@EnableWebSecurity
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(currentUserHandlerMethodArgumentResolver());
    }

    @Bean
    public HandlerMethodArgumentResolver currentUserHandlerMethodArgumentResolver() {
        return new HandlerMethodArgumentResolver() {
            @Override
            public boolean supportsParameter(MethodParameter methodParameter) {
                return methodParameter.getParameterType().equals(CustomPrincipal.class);
            }

            @Override
            public Object resolveArgument(MethodParameter methodParameter,
                                          ModelAndViewContainer modelAndViewContainer,
                                          NativeWebRequest nativeWebRequest,
                                          WebDataBinderFactory webDataBinderFactory) throws Exception {
                try {
                    return (CustomPrincipal) SecurityContextHolder
                            .getContext().getAuthentication().getPrincipal();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }
}
```

## Step 7
Due to the fact that we want to receive user email which is not contained in default values, we need to add it in 
UserAuthenticationConverter. So we need to create own converter.
```java
public class CustomUserAuthenticationConverter implements UserAuthenticationConverter {

    private final String EMAIL = "email";

    private Collection<? extends GrantedAuthority> defaultAuthorities;

    public void setDefaultAuthorities(String[] defaultAuthorities) {
        this.defaultAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList(StringUtils
                .arrayToCommaDelimitedString(defaultAuthorities));
    }

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(USERNAME, authentication.getName());

        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty())
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));

        return response;
    }

    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {
        if (map.containsKey(USERNAME))
            return new UsernamePasswordAuthenticationToken(
                    new CustomPrincipal(map.get(USERNAME).toString(), map.get(EMAIL).toString()), "N/A",
                    getAuthorities(map));
        return null;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Map<String,?> map) {
        if (!map.containsKey(AUTHORITIES))
            return  defaultAuthorities;

        Object authorities = map.get(AUTHORITIES);

        if (authorities instanceof String)
            return AuthorityUtils
                    .commaSeparatedStringToAuthorityList((String) authorities);
        if (authorities instanceof Collection)
            return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                    .collectionToCommaDelimitedString((Collection<?>) authorities));
        throw new IllegalArgumentException("Authorities must be either a String or a Collection");
    }
}
```

## Step 8
Finally, we need to add our CustomUserAuthenticationConverter to JwtAccessTokenConverter.
```java
@Component
public class CustomAccessTokenConverter implements AccessTokenConverter,
        JwtAccessTokenConverterConfigurer {

    private boolean includeGrantType;

    private UserAuthenticationConverter userTokenConverter = new CustomUserAuthenticationConverter();

    @Override
    public void configure(JwtAccessTokenConverter converter) {
        converter.setAccessTokenConverter(this);
    }

    @Override
    public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        OAuth2Request clientToken = authentication.getOAuth2Request();
        if (!authentication.isClientOnly())
            response.putAll(userTokenConverter.convertUserAuthentication(
                    authentication.getUserAuthentication()));
        else if (clientToken.getAuthorities() != null && !clientToken.getAuthorities().isEmpty())
            response.put(UserAuthenticationConverter.AUTHORITIES,
                    AuthorityUtils.authorityListToSet(clientToken.getAuthorities()));
        if (token.getScope() != null)
            response.put(SCOPE, token.getScope());

        if (token.getAdditionalInformation().containsKey(JTI))
            response.put(JTI, token.getAdditionalInformation().get(JTI));

        if (token.getExpiration() != null)
            response.put(EXP, token.getExpiration().getTime()/1000);

        if (includeGrantType && authentication.getOAuth2Request().getGrantType() != null)
            response.put(GRANT_TYPE, authentication.getOAuth2Request().getGrantType());

        response.putAll(token.getAdditionalInformation());
        response.put(CLIENT_ID, clientToken.getClientId());

        if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty())
            response.put(AUD, clientToken.getResourceIds());
        return response;
    }

    @Override
    public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map) {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(value);
        Map<String, Object> info = new HashMap<String, Object>(map);

        info.remove(EXP);
        info.remove(AUD);
        info.remove(CLIENT_ID);
        info.remove(SCOPE);

        if (map.containsKey(EXP))
            token.setExpiration(new Date((Long) map.get(EXP)*1000L));

        if(map.containsKey(JTI))
            info.put(JTI, map.get(JTI));

        token.setScope(extractScope(map));
        token.setAdditionalInformation(info);
        return token;
    }

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        Set<String> scope = extractScope(map);
        Map<String, String> parameters = new HashMap<>();
        Authentication user = userTokenConverter.extractAuthentication(map);

        String clientId = (String) map.get(CLIENT_ID);
        parameters.put(CLIENT_ID, clientId);

        if (includeGrantType && map.containsKey(GRANT_TYPE))
            parameters.put(GRANT_TYPE, (String) map.get(GRANT_TYPE));

        Set<String> resourceIds = new LinkedHashSet<>(
                map.containsKey(AUD)? getAudience(map) : Collections.<String> emptySet());
        Collection<? extends GrantedAuthority> authorities = null;

        if (user == null && map.containsKey(AUTHORITIES)) {
            @SuppressWarnings("unchecked")
                    String[] roles = ((Collection<String>) map.get(AUTHORITIES)).toArray(new String[0]);
            authorities = AuthorityUtils.createAuthorityList(roles);
        }
        OAuth2Request request = new OAuth2Request(parameters, clientId, authorities, true, scope,
                resourceIds, null, null, null);
        return new OAuth2Authentication(request, user);
    }

    private Set<String> extractScope(Map<String,?> map) {
        Set<String> scope = Collections.emptySet();
        if (map.containsKey(SCOPE)) {
            Object scopeObj = map.get(SCOPE);
            if (String.class.isInstance(scopeObj))
                scope = new LinkedHashSet<String>(
                        Arrays.asList(String.class.cast(scopeObj).split(" ")));
            else if (Collection.class.isAssignableFrom(scopeObj.getClass())) {
                @SuppressWarnings("unchecked")
                Collection<String> scopeCall = (Collection<String>) scopeObj;
                scope = new LinkedHashSet<>(scopeCall);
            }
        }
        return scope;
    }

    private Collection<String> getAudience(Map<String,?> map) {
        Object auds = map.get(AUD);

        if (auds instanceof Collection) {
            @SuppressWarnings("unchecked")
            Collection<String> result = (Collection<String>) auds;
            return result;
        }
        return Collections.singleton((String) auds);
    }

    public void setIncludeGrantType(boolean includeGrantType) {
        this.includeGrantType = includeGrantType;
    }

    public void setUserTokenConverter(UserAuthenticationConverter userTokenConverter) {
        this.userTokenConverter = userTokenConverter;
    }
}
```

## Step 9 
Run the project at http://localhost:9021/users using Postman.
Receive a token from authorization server and set it to Authorization field (type - Bearer token) 
with "Bearer " before the access token.


[Source](https://www.youtube.com/watch?v=fTAXXw-pKH8)