package com.example.securityACT.security;

import com.example.securityACT.auth.ApplicationUserService;
import com.example.securityACT.jwt.JwtTokenVerifier;
import com.example.securityACT.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.securityACT.security.ApplicationUserPermission.*;
import static com.example.securityACT.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())   // actually would want to use this with forms etc, but for now because we use postman and it's not a real website, it's disabled
//                .and()

                .csrf().disable()

                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)

                .authorizeRequests()

                //ROLES
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers(("/api/**")).hasRole(CUSTOMER.name())

                //AUTHORITIES
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(PRODUCT_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(PRODUCT_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(PRODUCT_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())

                .anyRequest()
                .authenticated()
//                .and()
//                .httpBasic()

//                .formLogin()
//                    .loginPage("/login").permitAll()
//                    .defaultSuccessUrl("/products", true)
//                    .passwordParameter("password") //can customise with these parameters
//                    .usernameParameter("username")
//                .and()

//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("averysecuredkey")
//                    .rememberMeParameter("remember-me")
//                .and()

//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //only when csrf is disabled, otherwise POST
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login")

                ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }





//    this is now done in the ApplicationUserService
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails fennLazarusUser = User.builder()
//                .username("fennlazarus")
//                .password(passwordEncoder.encode("password"))
////                .roles(CUSTOMER.name()) // ROLE_CUSTOMER
//                .authorities(CUSTOMER.getGrantedAuthorities())
//                .build();
//
//        UserDetails kimUser = User.builder()
//                .username("kim")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMIN.name()) // ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails elineUser = User.builder()
//                .username("eline")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                fennLazarusUser,
//                kimUser,
//                elineUser
//        );
//    }

}
