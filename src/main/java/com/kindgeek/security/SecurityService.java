package com.kindgeek.security;

import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

public interface SecurityService {

    boolean isTokenValid(String token);

    boolean isTokenExpired(String authToken);

    boolean checkClientIp(HttpServletRequest httpServletRequest, String token);

    boolean checkSessionId(HttpServletRequest httpServletRequest, String token);

    UserDetails getUserByToken(String token);
}
