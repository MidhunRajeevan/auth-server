package authx.auth_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientRowMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import java.security.KeyPair;
import com.nimbusds.jose.jwk.RSAKey;

import javax.sql.DataSource;


@Configuration
public class SecurityConfig {

	@Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String username;

    @Value("${spring.datasource.password}")
    private String password;

    @Value("${spring.datasource.driver-class-name}")
    private String driverClassName;


    // @Bean
    // SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // http.csrf(csrf -> csrf.disable())  // Disable CSRF protection
    //     .authorizeHttpRequests(authorizeRequests -> authorizeRequests
    //         .requestMatchers( "/register-client").hasAuthority("admin")
    //         .requestMatchers("/tigo").hasAuthority("ViewAccount")
    //         .anyRequest().authenticated()
    //     )
    //     .formLogin(withDefaults())  // Configure form-based login
    //     .httpBasic(withDefaults());  // Configure HTTP Basic authentication

    //     return http.build();
    // }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean 
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults());

		return http.build();
	}

	@Bean 
	public ApplicationRunner applicationRunner(RegisteredClientRepository registeredClientRepository) {
		return args -> {

			if (registeredClientRepository.findByClientId("admin1")==null) {
				RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId("admin1")
					.clientSecret("{bcrypt}$2a$10$vEcnFKH4tk9idrMYz8y0X.H0OFNZ/c77ntpe02nJCtNIYemukT9eq")
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.postLogoutRedirectUri("http://127.0.0.1:8080/")
					.scope(OidcScopes.OPENID)
					.scope(OidcScopes.PROFILE)
					.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
					.build();
	
					registeredClientRepository.save(oidcClient);
			}
		};
		
		
	}
	// @Bean 
	// public RegisteredClientRepository registeredClientRepository() {
	// 	RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
	// 			.clientId("admin")
	// 			.clientSecret("{noop}admin@123")
	// 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	// 			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	// 			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	// 			.scopes(scopeConfig->scopeConfig.addAll(List.of(OidcScopes.OPENID,"admin","user")))
    //             .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)).
    //              accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
	// 			.build();

	// 	return new InMemoryRegisteredClientRepository(oidcClient);
	// }

	@Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

	@Bean 
	public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() { 
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean 
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwTokenCustomizer(){

		return(context) ->{
			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
				
				context.getClaims().claims((claims)-> claims.put("roles", "business_admin"));
			}
		};
	}

}
