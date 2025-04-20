package com.blog.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Get the token from the Authorization header
        String requestToken = request.getHeader("Authorization");

        System.out.println("Authorization Header: " + requestToken);  // Logging for debugging

        String username = null;
        String token = null;

        // 2. Check if the token starts with "Bearer " and extract the token
        if (requestToken != null && requestToken.startsWith("Bearer ")) {
            token = requestToken.substring(7);  // Remove "Bearer " prefix

            try {
                // 3. Get the username from the token
                username = this.jwtTokenHelper.getUsernameFromToken(token);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT token: " + e.getMessage());
            } catch (ExpiredJwtException e) {
                System.out.println("JWT token has expired: " + e.getMessage());
            } catch (MalformedJwtException e) {
                System.out.println("Invalid JWT: " + e.getMessage());
            }
        } else {
            System.out.println("JWT token does not begin with Bearer");
        }

        // 4. If the token is valid and username is found, authenticate the user
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (this.jwtTokenHelper.validateToken(token, userDetails)) {
                // 5. Set the authentication context with the user details
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                System.out.println("User authenticated successfully");
            } else {
                System.out.println("Invalid JWT token");
            }
        } else {
            System.out.println("Username is null or context is not null");
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
