package com.springsecurity.spr_security.dao;

import com.springsecurity.spr_security.entiry.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class DBInit implements CommandLineRunner {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {

        userRepository.deleteAll();

        User user = new User("user", "user", passwordEncoder.encode("1234"), "USER", "" );
        User user1 = new User("user1", "user1", passwordEncoder.encode("1234"), "USER", "ACCESS_PROFILE" );
        User manager = new User("manager", "manager", passwordEncoder.encode("1234"), "MANAGER", "" );
        User admin = new User("admin", "admin", passwordEncoder.encode("1234"), "ADMIN", "" );

        List<User> users = Arrays.asList(user, user1, manager, admin);

        userRepository.saveAll(users);
    }
}
