package authx.auth_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

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
    //     http.csrf(csrfconfig->csrfconfig.disable());
    //     http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
    //     http.authorizeHttpRequests((request)->request.requestMatchers("/notification","register-client").permitAll());
    //     http.formLogin(withDefaults());
    //     http.httpBasic(withDefaults());
    //     return http.build();
    // }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())  // Disable CSRF protection
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests
            .requestMatchers("/notification", "/register-client").permitAll()  // Permit these endpoints without authentication
            .anyRequest().authenticated()  // Authenticate other requests
        )
        .formLogin(withDefaults())  // Configure form-based login
        .httpBasic(withDefaults());  // Configure HTTP Basic authentication

    return http.build();
}

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
