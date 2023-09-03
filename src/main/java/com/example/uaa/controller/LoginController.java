package com.example.uaa.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(HttpServletRequest request) {
        System.out.printf("client_id: %s \n", request.getParameter("client_id"));
        return "login";
    }

    @GetMapping("/custom-login")
    public String customLogin(HttpServletRequest request) {
        System.out.printf("client_id: %s \n", request.getParameter("client_id"));
        return "custom-login";
    }
}
