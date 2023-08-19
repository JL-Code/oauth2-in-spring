package com.example.uaa.service.impl;

import com.example.uaa.entity.Account;
import com.example.uaa.service.AccountService;
import com.example.uaa.service.OidcUserInfoService;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
public class OidcUserInfoServiceImpl implements OidcUserInfoService {

    final AccountService accountService;

    public OidcUserInfoServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public OidcUserInfo loadUser(String username) {
        Account account = accountService.findByName(username);
        return OidcUserInfo.builder()
                .email(account.getEmail())
                .name(account.getUsername())
                .subject(account.getId())
                .claim("type", account.getType())
                .picture(account.getAvatar())
                .build();
    }
}
