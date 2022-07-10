package me.g1tommy.samplereactivesecurityjwt.config.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("service.jwt")
public class JwtTokenProperties {
    private String secret;
    private String expirationTime;
}
