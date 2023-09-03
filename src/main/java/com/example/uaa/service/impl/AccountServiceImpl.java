package com.example.uaa.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.uaa.dao.AccountDao;
import com.example.uaa.entity.Account;
import com.example.uaa.service.AccountService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
@Slf4j
public class AccountServiceImpl extends ServiceImpl<AccountDao, Account> implements AccountService {

    final String ACCOUNT_TYPE = "MEMBER";

    @Override
    public void register(Account account) {
        var timestamp = LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC);
        account.setId(String.valueOf(timestamp));
        save(account);
    }

    @Override
    public void register(String registrationId, OAuth2User user) {
        var account = extract(registrationId, user);
        register(account);
    }

    @Override
    public Account extract(String registrationId, OAuth2User user) {
        var account = Account.newAccount();
        if (OAuth2ProviderNames.GITHUB.equals(registrationId)) {
            account.setEmail(user.getAttribute(OidcScopes.EMAIL));
            account.setType(ACCOUNT_TYPE);
            account.setAvatar(user.getAttribute("avatar_url"));
            account.setGithubUid(user.getName());
            return account;
        } else if (OAuth2ProviderNames.GOOGLE.equals(registrationId)) {
            account.setEmail(user.getAttribute(OidcScopes.EMAIL));
            account.setType(ACCOUNT_TYPE);
            account.setAvatar(user.getAttribute("picture"));
            account.setGoogleUid(user.getName());
            return account;
        } else {
            log.warn("位置的 OAuth2 Provider Name: {}", registrationId);
        }
        return null;
    }

    @Override
    public Account findByName(String username) {
        var query = Wrappers.<Account>lambdaQuery()
                .eq(Account::getUsername, username)
                .or()
                .eq(Account::getEmail, username)
                .or()
                .eq(Account::getGithubUid, username)
                .or()
                .eq(Account::getGoogleUid, username)
                .or()
                .eq(Account::getFacebookUid, username);
        return getOne(query);
    }

    static class OAuth2ProviderNames {
        public static final String GOOGLE = "google";
        public static final String GITHUB = "github";
    }
}
