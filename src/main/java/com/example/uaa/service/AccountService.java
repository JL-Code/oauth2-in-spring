package com.example.uaa.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.uaa.entity.Account;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * 账号服务
 */
public interface AccountService extends IService<Account> {
    void register(Account account);
    void register(String registrationId, OAuth2User user);

    Account extract(String registrationId, OAuth2User user);

    Account findByName(String username);
}
