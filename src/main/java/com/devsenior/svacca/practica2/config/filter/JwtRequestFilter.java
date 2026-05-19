package com.devsenior.svacca.practica2.config.filter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.devsenior.svacca.practica2.util.JwtUtil;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            var token = header.substring(7);
            if (jwtUtils.validateToken(token)) {
                var username = jwtUtils.extractClaims(token, Claims::getSubject);
                var email = jwtUtils.extractClaims(token, (claims) -> claims.get("email", String.class));
                var name = jwtUtils.extractClaims(token, (claims) -> claims.get("name", String.class));
                var hireDate = jwtUtils.extractClaims(token, (claims) -> claims.get("hire_date", String.class));
                var roles = jwtUtils.extractClaims(token, (claims) -> {
                    var result = new HashSet<SimpleGrantedAuthority>();
                    var info = claims.get("roles", List.class);
                    for (var item : info) {
                        result.add(new SimpleGrantedAuthority(item.toString()));
                    }
                    return result;

                });

                var userToken = new UsernamePasswordAuthenticationToken(
                        Map.of(
                                "username", username,
                                "email", email,
                                "name", name,
                                "hire_date", hireDate),
                        "",
                        roles);

                SecurityContextHolder.getContext().setAuthentication(userToken);
            }
        }
        // Se continua al sigueitne paso
        filterChain.doFilter(request, response);
    }
}
