package com.springsecurity.spr_security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    UserPrincipalDetailsService userPrincipalDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {

        /** roles based authentication **/
//        auth
//                .inMemoryAuthentication()
//                .withUser("admin").password(passwordEncoder().encode("1234")).roles("ADMIN")
//                .and()
//                .withUser("user").password(passwordEncoder().encode("1234")).roles("USER")
//                .and()
//                .withUser("manager").password(passwordEncoder().encode("1234")).roles("MANAGER");


        /** permission based authentication **/
//                auth
//                .inMemoryAuthentication()
//                .withUser("admin").password(passwordEncoder().encode("1234")).roles("ADMIN")
//                .and()
//                .withUser("user").password(passwordEncoder().encode("1234")).roles("USER")
//                .and()
//                .withUser("user1")
//                        .password(passwordEncoder()
//                                .encode("1234"))
////                        .roles("USER")
//                        // for mixing role and authority
//                        .authorities("ACCESS_PROFILE", "ROLE_USER")
//                .and()
//                .withUser("manager").password(passwordEncoder().encode("1234")).roles("MANAGER");


        /** [Database   authentication] **/

        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /** simple authentication on http basic **/
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .httpBasic();

        /** role based simple authentication on http basic
         *
         *
         * findings: have to matched exect path
         * like ---- /admin [antMatchers have to be /admin]
         * like ---- /admin/ [antMatchers have to be /admin/]
         *
         * antMatchers -> action [in the chain]
         *
         * **/

        http
                .authorizeRequests()
                .antMatchers("/home/").authenticated()
                /** role based **/
                .antMatchers("/admin/").hasRole("ADMIN")
                .antMatchers("/user/").hasAnyRole("USER", "ADMIN", "MANAGER")
                .antMatchers("/manager/").hasAnyRole("MANAGER", "ADMIN")
                /** permission based
                 *
                 * [if we use roles and permission roles will not work because authority hsa precedence
                 * authority come before roles in-terms of priority]
                 *
                 * **/
                .antMatchers("/profile/").hasAuthority("ACCESS_PROFILE")
                .anyRequest().authenticated()
                .and()
                /** [http basic ] **/
//                .httpBasic();
                 /** [form based authentication] **/
                 .formLogin()
                .loginProcessingUrl("/login")
                .loginPage("/login").permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout-now")).invalidateHttpSession(true).deleteCookies("JSESSIONID").logoutSuccessUrl("/login")
                .and()
                .rememberMe().tokenValiditySeconds(54665465).key("secret").rememberMeParameter("remember");
    }

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);
        return authenticationProvider;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
