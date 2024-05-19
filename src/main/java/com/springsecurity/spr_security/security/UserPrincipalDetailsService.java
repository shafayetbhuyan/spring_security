package com.springsecurity.spr_security.security;

import com.springsecurity.spr_security.dao.UserRepository;
import com.springsecurity.spr_security.entiry.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserPrincipalDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUserName(username);
        UserPrincipal userPrincipal = new UserPrincipal(user);
        return userPrincipal;
    }

}
