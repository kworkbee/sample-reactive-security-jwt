package me.g1tommy.samplereactivesecurityjwt.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class AuthenticatedUser {
    private String name;
}
