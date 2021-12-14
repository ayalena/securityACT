package com.example.securityACT.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.securityACT.security.ApplicationUserRole.ADMIN;
import static com.example.securityACT.security.ApplicationUserRole.CUSTOMER;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers(("/api/**")).hasRole(CUSTOMER.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic()
                ;
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails fennLazarusUser = User.builder()
                .username("fennlazarus")
                .password(passwordEncoder.encode("password"))
                .roles(CUSTOMER.name()) // ROLE_CUSTOMER
                .build();

        UserDetails kimUser = User.builder()
                .username("kim")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name()) // ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(
                fennLazarusUser,
                kimUser
        );
    }
}
