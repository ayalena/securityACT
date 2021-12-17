package com.example.securityACT.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey,
                            JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    //executed once per request (coming from client)
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //get token from header
//        String authorizationHeader = request.getHeader("Authorization");
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());


        //reject if no header/doesn't start with bearer
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        //if it does:
        try {
            //parse the token
//            String secretKey = "secureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKeysecureStrongAndVeryLongKey";
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            //get body
            Claims body = claimsJws.getBody();

            //retrieve subject from body (user!)
            String username = body.getSubject();

            //get authorities from body (list of maps)
            var authorities = ((List<Map<String, String>>) body.get("authorities"));

            //map authorities from token (needed to extend collection of authorities)
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            //tell spring security that this user from now on can be authenticated
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities);

            //authenticate client that sent the token
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //catch exception
        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        //makes sure that request en response can be transferred to next filter
        filterChain.doFilter(request, response);

    }
}
