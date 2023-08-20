package com.example.uaa.security.jdbc.service.impl;

import com.example.uaa.entity.Account;
import com.example.uaa.service.AccountService;
import com.example.uaa.user.UserProxy;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Primary
public class UserServiceImpl implements UserDetailsService {
    final AccountService accountService;

    public UserServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountService.findByName(username);
        if(account == null){
            throw new UsernameNotFoundException(username);
        }
        return new UserProxy<>(account);
    }
}
