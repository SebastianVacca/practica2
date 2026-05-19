package com.devsenior.svacca.practica2.service.impl;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("user".equals(username)) {
            return new User("user", "$2a$10$SlYQmyglfiGw/YgE/M7F7.y0Uq0Xk0K0Xk0K0Xk0K0Xk0K0Xk0K", new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("Usuario no encontrado: " + username);
        }
    }
}
