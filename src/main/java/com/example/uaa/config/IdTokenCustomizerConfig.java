//package com.example.uaa.config;
//
//import com.example.uaa.service.OidcUserInfoService;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
//import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
//import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
//import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
//
///**
// * 将自定义的声明添加到 IdToken，从而改变 /userinfo 的响应结果 示例：
// */
//@Configuration
//public class IdTokenCustomizerConfig {
//
//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
//            OidcUserInfoService userInfoService) {
//        return (context) -> {
//            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
//                OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());
//                context.getClaims().claims(claims ->
//                        claims.putAll(userInfo.getClaims()));
//            }
//        };
//    }
//}
