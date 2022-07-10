package me.g1tommy.samplereactivesecurityjwt.config.security;

import me.g1tommy.samplereactivesecurityjwt.config.jwt.JwtTokenAuthenticationFilter;
import me.g1tommy.samplereactivesecurityjwt.config.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;

@EnableWebFluxSecurity
public class ReactiveSecurityConfig {

    private static final String ALL_PATHS = "/**";
    private static final String AUTHENTICATION_ENTRYPOINT = "/auth/login";

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http,
                                                      JwtTokenProvider jwtTokenProvider) {
        // @formatter:off
        return http
                .cors().disable()
                .csrf().disable()
                .headers().frameOptions().disable().and()
                .authorizeExchange()
                    .pathMatchers(HttpMethod.OPTIONS, ALL_PATHS).permitAll()
                    .pathMatchers(AUTHENTICATION_ENTRYPOINT).permitAll()
                    .anyExchange().authenticated().and()
                .exceptionHandling()
                    .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)).and()
                .httpBasic().disable()
                .formLogin().disable()
                .addFilterAt(new JwtTokenAuthenticationFilter(jwtTokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
                .logout().disable()
                .build();
        // @formatter:on
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("admin"))
                .roles("ADMIN", "USER")
                .build();
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("user"))
                .roles("USER")
                .build();

        return new MapReactiveUserDetailsService(admin, user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Pbkdf2PasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager(ReactiveUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);

        return authenticationManager;
    }
}
