package com.example.uaa.security;

import com.example.uaa.service.AccountService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.function.BiConsumer;

/**
 * 联合登录时，自动注册用户到系统示例：
 * 首次身份验证时捕获本地数据存储中的用户
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Slf4j
@Component
public class UserRepositoryOAuth2UserHandler implements BiConsumer<String, OAuth2User> {


    private final AccountService accountService;

    public UserRepositoryOAuth2UserHandler(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public void accept(String registrationId, OAuth2User user) {
        // Capture user in a local data store on first authentication
        // 首次身份验证时捕获本地数据存储中的用户
        var account = accountService.findByName(user.getName());
        if (account == null) {
            log.info("Saving first-time user: name=" + user.getName() + ", claims=" + user.getAttributes() + ", authorities=" + user.getAuthorities());
            this.accountService.register(registrationId, user);
            // 使用系统中的用户信息更新 OAuth2User
        } else {
            // 使用系统中的用户信息更新 OAuth2User
            log.info("当前用户已经在系统中存在了, name: {}", user.getName());
        }
    }

}
