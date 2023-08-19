package com.example.uaa.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.uaa.dao.AccountDao;
import com.example.uaa.entity.Account;
import com.example.uaa.service.AccountService;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountDao, Account> implements AccountService {

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
        if ("github".equals(registrationId)) {
            account.setEmail(user.getAttribute(OidcScopes.EMAIL));
            account.setType("MEMBER");
            account.setAvatar(user.getAttribute("avatar_url"));
            account.setGithubUid(user.getName());
            return account;
        }
        return null;
    }

    @Override
    public Account findByName(String username) {
        var query = Wrappers.<Account>lambdaQuery()
                .eq(Account::getUsername, username)
                .or()
                .eq(Account::getGithubUid, username);
        return getOne(query);
    }
}
