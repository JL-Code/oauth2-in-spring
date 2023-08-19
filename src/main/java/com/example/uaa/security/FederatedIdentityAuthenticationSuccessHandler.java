package com.example.uaa.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * TODO: Capture Users in a Database
 * 以下示例 AuthenticationSuccessHandler 使用自定义组件在本地数据库中捕获首次登录的用户：
 * 联合身份认证成功处理器
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Component
public class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private BiConsumer<String, OAuth2User> oauth2UserHandler = (registrationId, user) -> {
    };

    private BiConsumer<String, OidcUser> oidcUserHandler = (registrationId, user) -> this.oauth2UserHandler.accept(registrationId, user);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken token) {
            // 通过 authorizedClientRegistrationId 字段判断登录身份来至哪个提供商。
            String registrationId = token.getAuthorizedClientRegistrationId();
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                this.oidcUserHandler.accept(registrationId, oidcUser);
            } else if (authentication.getPrincipal() instanceof OAuth2User oauth2User) {
                this.oauth2UserHandler.accept(registrationId, oauth2User);
            }
            // TODO: 想办法使用本系统的用户信息更新 SecurityContext 中的 Authentication
            // https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-userinfo.html#customize-id-token
//            var oauthUser = new DefaultOAuth2User(null, null,"name");
//            var newToken = new OAuth2AuthenticationToken(oauthUser, null, registrationId);
//            SecurityContextHolder.getContext().setAuthentication(newToken);

        }
        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }

    public void setOAuth2UserHandler(BiConsumer<String, OAuth2User> oauth2UserHandler) {
        this.oauth2UserHandler = oauth2UserHandler;
    }

    public void setOidcUserHandler(BiConsumer<String, OidcUser> oidcUserHandler) {
        this.oidcUserHandler = oidcUserHandler;
    }
}
