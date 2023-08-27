package com.example.uaa.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @GetMapping("/unauthorized")
    public String unauthorized() {
        return "unauthorized";
    }

    @GetMapping("/error")
    public String error() {
        return "error";
    }
}
