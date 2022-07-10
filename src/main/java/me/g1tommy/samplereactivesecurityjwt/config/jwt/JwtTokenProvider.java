package me.g1tommy.samplereactivesecurityjwt.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import me.g1tommy.samplereactivesecurityjwt.domain.AuthenticatedUser;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtTokenProperties.class)
public class JwtTokenProvider {

    private static final String AUTHORITIES_KEY = "permissions";

    private final JwtTokenProperties jwtTokenProperties;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        String secret = Base64.getEncoder().encodeToString(jwtTokenProperties.getSecret().getBytes());
        secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(Authentication authentication) {
        String username = authentication.getName();
        long expirationTime = Long.parseLong(jwtTokenProperties.getExpirationTime());
        final Date createdDate = new Date();
        final Date expirationDate = new Date(createdDate.getTime() + expirationTime);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(secretKey)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaimsJws(token).getBody();

        Object authoritiesClaim = claims.get(AUTHORITIES_KEY);

        Collection<? extends GrantedAuthority> authorities = authoritiesClaim == null ?
                AuthorityUtils.NO_AUTHORITIES :
                AuthorityUtils.commaSeparatedStringToAuthorityList(
                        authoritiesClaim.toString());

        AuthenticatedUser user = AuthenticatedUser.builder()
                .name(claims.getSubject())
                .build();
        return new UsernamePasswordAuthenticationToken(user, token, authorities);
    }

    public boolean validateToken(String token) {
        try {
            getClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }

    private Jws<Claims> getClaimsJws(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
    }

}
