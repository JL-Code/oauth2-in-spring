package com.example.uaa.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(HttpServletRequest request) {
        System.out.printf("client_id: %s \n", request.getParameter("client_id"));
        return "login";
    }

    @GetMapping("/custom-login")
    public String customLogin(Model model, @RequestParam String client_id) {
        System.out.printf("client_id: %s \n", client_id);
        model.addAttribute("client_id", client_id);
        return "custom-login";
    }
}
