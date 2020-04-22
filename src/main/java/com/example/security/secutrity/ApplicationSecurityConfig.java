package com.example.security.secutrity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.security.secutrity.UserPermission.COURSE_WRITE;
import static com.example.security.secutrity.UserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                // all can access this
                .antMatchers("/","index", "/css/*", "/js/*").permitAll()
                // only student role can access
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // only admin can access it
/*
                .antMatchers( HttpMethod.POST,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers( HttpMethod.DELETE,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers( HttpMethod.PUT,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
*/
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("something very securied key")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    // when it is disable .csrf().disable()
                    // we have to do it as follows
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");

    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails dev = User.builder()
                .username("dev")
                .password(passwordEncoder.encode("dev"))
                // we can do role based UserDetails
                //.roles(STUDENT.name())
                // Also we can do authority base UserDetails
                .authorities(STUDENT.grantedAuthorities())
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("dev"))
                // we can do role based UserDetails
                //.roles(ADMIN.name())
                // Also we can do authority base UserDetails
                .authorities(ADMIN.grantedAuthorities())
                .build();

        UserDetails adminTrainee = User.builder()
                .username("trainee")
                .password(passwordEncoder.encode("temp"))
                // we can do role based UserDetails
                //.roles(ADMIN_TRAINEE.name())
                // Also we can do authority base UserDetails
                .authorities(ADMIN_TRAINEE.grantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                dev, admin, adminTrainee);
    }

}
