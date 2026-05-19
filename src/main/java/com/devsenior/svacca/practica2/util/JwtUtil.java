package com.devsenior.svacca.practica2.util;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String generatedToken(String subject, Map<String, Object> claims) {
        return Jwts.builder()
            .subject(subject)
            .claims(claims)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSignInKey())
            .compact();
    }

    private SecretKey getSignInKey() {
        byte[] keyBites = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBites);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        var claims = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claimsResolver.apply(claims);
    }

    public boolean validateToken(String token) {
        var exp = extractClaims(token, Claims::getExpiration);
        return(exp.before(new Date())) ? false : true;
    }

}
