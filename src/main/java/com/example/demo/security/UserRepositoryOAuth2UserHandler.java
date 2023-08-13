package com.example.demo.security;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Component
public class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final UserRepository userRepository = new UserRepository();

    @Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        if (this.userRepository.findByName(user.getName()) == null) {
            System.out.println("Saving first-time user: name=" + user.getName() + ", claims=" + user.getAttributes() + ", authorities=" + user.getAuthorities());
            this.userRepository.save(user);
        }
    }

    static class UserRepository {

        private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

        public OAuth2User findByName(String name) {
            return this.userCache.get(name);
        }

        public void save(OAuth2User oauth2User) {
            this.userCache.put(oauth2User.getName(), oauth2User);
        }

    }
}
