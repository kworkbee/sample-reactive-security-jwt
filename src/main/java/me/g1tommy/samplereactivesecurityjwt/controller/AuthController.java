package me.g1tommy.samplereactivesecurityjwt.controller;

import lombok.RequiredArgsConstructor;
import me.g1tommy.samplereactivesecurityjwt.config.jwt.JwtTokenProvider;
import me.g1tommy.samplereactivesecurityjwt.domain.dto.AuthenticatedTokenDto;
import me.g1tommy.samplereactivesecurityjwt.domain.dto.LoginDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static org.springframework.http.ResponseEntity.ok;
import static org.springframework.http.ResponseEntity.status;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final ReactiveAuthenticationManager authenticationManager;

    @PostMapping("/login")
    public Mono<ResponseEntity<?>> login(@RequestBody Mono<LoginDto> loginDtoMono) {
        return loginDtoMono.flatMap(dto -> {
            var authentication = new UsernamePasswordAuthenticationToken(
                    dto.userId(), dto.userPw()
            );

            return authenticationManager.authenticate(authentication)
                    .map(jwtTokenProvider::createToken)
                    .map(AuthenticatedTokenDto::new)
                    .map(ok()::body)
                    .onErrorReturn(AuthenticationException.class, status(HttpStatus.UNAUTHORIZED)
                            .body(new AuthenticatedTokenDto(null)));
        });
    }
}
