package com.example.uaa.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@RestController
public class HomeController {
    @GetMapping("/")
    public String home() {
        return "home";
    }

}
