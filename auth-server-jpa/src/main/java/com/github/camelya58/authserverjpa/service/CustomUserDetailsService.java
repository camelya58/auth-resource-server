package com.github.camelya58.authserverjpa.service;

import com.github.camelya58.authserverjpa.model.User;
import com.github.camelya58.authserverjpa.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Class CustomUserDetailsService contains a single method of interface UserDetailsService.
 *
 * @author Kamila Meshcheryakova
 * created 04.08.2020
 */
@Service(value = "userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);

        if (user == null)
            throw new BadCredentialsException("Bad Credentials");
        new AccountStatusUserDetailsChecker().check(user);

        return user;
    }
}
