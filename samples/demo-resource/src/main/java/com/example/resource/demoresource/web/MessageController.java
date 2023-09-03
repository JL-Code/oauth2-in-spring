package com.example.resource.demoresource.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * <p>创建时间: 2023/8/27 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@RestController
public class MessageController {
    @GetMapping("/messages")
    public List<String> showMessage() {
        return List.of("message1", "message2", "message3");
    }

}
