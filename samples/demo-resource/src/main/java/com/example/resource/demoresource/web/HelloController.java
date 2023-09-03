package com.example.resource.demoresource.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>创建时间: 2023/8/27 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String sayHello(String msg) {
        return "hello," + msg;
    }

}
