package com.example.uaa.controller;

import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Slf4j
@RestController
public class UserController {
    @GetMapping("/account-validations")
    public String validateAccount(String username) {
        return username;
    }

    @GetMapping("/api/oauth2/attributes")
    public Map<String, Object> getOAuth2Attributes(@AuthenticationPrincipal OAuth2User user) {
        return user.getAttributes();
    }

    @GetMapping("/api/oidc/attributes")
    public Object getOidcAttributes() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("username: {}", name);
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("principal: {}", principal);
        return principal;

    }
}
