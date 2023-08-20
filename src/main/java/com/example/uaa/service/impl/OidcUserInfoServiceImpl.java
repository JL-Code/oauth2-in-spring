package com.example.uaa.service.impl;

import com.example.uaa.entity.Account;
import com.example.uaa.service.AccountService;
import com.example.uaa.service.OidcUserInfoService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OidcUserInfoServiceImpl implements OidcUserInfoService {

    final AccountService accountService;

    public OidcUserInfoServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public OidcUserInfo loadUser(String username) {
        Account account = accountService.findByName(username);
        var userinfo= OidcUserInfo.builder()
                .email(account.getEmail())
                .name(account.getUsername())
                .subject(account.getId())
                .claim("type", account.getType())
                .picture(account.getAvatar())
                .build();

        log.info("oidc userinfo: {}",userinfo);
        return userinfo;
    }
}
