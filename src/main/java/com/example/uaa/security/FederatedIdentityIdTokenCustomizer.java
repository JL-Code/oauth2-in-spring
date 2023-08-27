package com.example.uaa.security;

import com.example.uaa.service.OidcUserInfoService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.*;

/**
 * Map Claims to an ID Token
 * 以下示例 OAuth2TokenCustomizer 将用户声明从身份验证提供程序映射到 Spring 授权服务器生成的声明 id_token ：
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Slf4j
public final class FederatedIdentityIdTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private static final Set<String> ID_TOKEN_CLAIMS = Set.of(
            IdTokenClaimNames.ISS,
            IdTokenClaimNames.SUB,
            IdTokenClaimNames.AUD,
            IdTokenClaimNames.EXP,
            IdTokenClaimNames.IAT,
            IdTokenClaimNames.AUTH_TIME,
            IdTokenClaimNames.NONCE,
            IdTokenClaimNames.ACR,
            IdTokenClaimNames.AMR,
            IdTokenClaimNames.AZP,
            IdTokenClaimNames.AT_HASH,
            IdTokenClaimNames.C_HASH
    );

    final OidcUserInfoService userInfoService;

    public FederatedIdentityIdTokenCustomizer(OidcUserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    /**
     * 定制 Spring Security JWT
     *
     * @param context JwtEncodingContext
     */
    @Override
    public void customize(JwtEncodingContext context) {
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {

            Map<String, Object> thirdPartyClaims = extractClaims(context.getPrincipal());
            OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());
            context.getClaims().claims(claims ->
                    claims.putAll(userInfo.getClaims()));

            context.getClaims().claims(existingClaims -> {
                // Remove conflicting claims set by this authorization server
                // 删除此授权服务器设置的冲突声明
                existingClaims.keySet().forEach(thirdPartyClaims::remove);
                // Remove standard id_token claims that could cause problems with clients
                // 删除可能导致客户端出现问题的标准id_token声明
                ID_TOKEN_CLAIMS.forEach(thirdPartyClaims::remove);
                // Add all other claims directly to id_token
                // 将所有其他声明直接添加到id_token
//                existingClaims.putAll(thirdPartyClaims);
            });
        } else if ("access_token".equals(context.getTokenType().getValue())) {
            Map<String, Object> thirdPartyClaims = extractClaims(context.getPrincipal());
            log.info("thirdPartyClaims: {}", thirdPartyClaims);
        }
    }

    /**
     * 从 Authentication 对象中提取出用户声明信息
     *
     * @param principal 认证主体
     * @return Map
     */
    private Map<String, Object> extractClaims(Authentication principal) {
        Map<String, Object> claims;
        if (principal.getPrincipal() instanceof OidcUser oidcUser) {
            OidcIdToken idToken = oidcUser.getIdToken();
            claims = idToken.getClaims();
        } else if (principal.getPrincipal() instanceof OAuth2User oauth2User) {
            claims = oauth2User.getAttributes();
        } else {
            claims = Collections.emptyMap();
        }

        return new HashMap<>(claims);
    }
}
