package com.example.uaa.config;

import com.example.uaa.security.CustomAuthenticationEntryPoint;
import com.example.uaa.security.FederatedIdentityAuthenticationSuccessHandler;
import com.example.uaa.security.FederatedIdentityIdTokenCustomizer;
import com.example.uaa.security.UserRepositoryOAuth2UserHandler;
import com.example.uaa.service.OidcUserInfoService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * 安全配置类
 * 1. 协议端点的 Spring 安全过滤器链。
 * 2. 配置 用于 AuthenticationEntryPoint 重定向到 OAuth 2.0 登录端点。
 * 3. 用于身份验证的 Spring 安全性筛选器链。
 * 4. 配置 OAuth 2.0 登录以进行身份验证。
 * <p>创建时间: 2023/8/13 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JdbcTemplate jdbcTemplate;
    private final UserDetailsService userDetailsService;
    private final OidcUserInfoService oidcUserInfoService;
    private final FederatedIdentityAuthenticationSuccessHandler authenticationSuccessHandler;
    private final UserRepositoryOAuth2UserHandler userRepositoryOAuth2UserHandler;

    public SecurityConfig(JdbcTemplate jdbcTemplate,
                          UserDetailsService userDetailsService, OidcUserInfoService oidcUserInfoService,
                          FederatedIdentityAuthenticationSuccessHandler authenticationSuccessHandler,
                          UserRepositoryOAuth2UserHandler userRepositoryOAuth2UserHandler) {
        this.jdbcTemplate = jdbcTemplate;
        this.userDetailsService = userDetailsService;
        this.oidcUserInfoService = oidcUserInfoService;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.userRepositoryOAuth2UserHandler = userRepositoryOAuth2UserHandler;
    }

    /**
     * OAuth2 Token 定制器
     *
     * @return OAuth2 Token 定制器实例
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new FederatedIdentityIdTokenCustomizer(oidcUserInfoService);
    }

    // region 社交登录配置

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://127.0.0.1:4200");
        config.addAllowedOrigin("http://localhost:4200");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // 密码加密器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // Enable OpenID Connect 1.0
                .oidc(Customizer.withDefaults());
//                .tokenGenerator();
        http.cors(Customizer.withDefaults())
                .userDetailsService(userDetailsService)
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new CustomAuthenticationEntryPoint("/custom-login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                // 开启跨域访问
                .cors(Customizer.withDefaults())
                // OAuth2 Login handles the redirect to the OAuth 2.0 Login endpoint
                // from the authorization server filter chain
                .formLogin(formLogin -> {
                    formLogin.loginPage("/login")
                            .permitAll();
                })
                .oauth2Login(oauth2Login -> {
                    // 设置自定义登录页面（设置后,默认生成的登录及退出页面的过滤器将不会被添加到 Filters 中。）
                    oauth2Login.loginPage("/login");
                    // 认证成功后回调处理，eg：保存第一次登录的用户信息。
                    authenticationSuccessHandler.setOAuth2UserHandler(userRepositoryOAuth2UserHandler);
                    oauth2Login.successHandler(authenticationSuccessHandler);
                })
                .oauth2ResourceServer(oauth2ResourceServer -> {
                    // Add BearerTokenAuthenticationFilter 支持从 JWT 中恢复认证信息。
                    oauth2ResourceServer.jwt(Customizer.withDefaults());
                });
        return http.build();
    }

    /**
     * Web Security 自定义器
     */
//    @Bean
//    WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) ->
//                web.debug(false)
//                        .ignoring()
//                        .requestMatchers("/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico");
//
//    }

    // endregion

//    /**
//     * 用户信息服务
//     * An instance of UserDetailsService for retrieving users to authenticate.
//     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user1")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    /**
     * OAuth2 Client 仓库
     * An instance of RegisteredClientRepository for managing clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        var publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client")
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .postLogoutRedirectUri("http://127.0.0.1:4200")
                .postLogoutRedirectUri("http://localhost:4200")
                .redirectUri("http://127.0.0.1:4200")
                .redirectUri("http://localhost:4200")
                .redirectUri("http://127.0.0.1:4200/auth/callback")
                .redirectUri("http://localhost:4200/auth/callback")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.of(1, ChronoUnit.HOURS)).build())
                .build();
//
//        return new InMemoryRegisteredClientRepository(publicClient);
        // 使用 JDBC
        var repo = new JdbcRegisteredClientRepository(jdbcTemplate);
        if (repo.findByClientId("public-client") == null) {
            repo.save(publicClient);
        }
        return repo;
    }

    /**
     * An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * An instance of JwtDecoder for decoding signed access tokens.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * An instance of AuthorizationServerSettings to configure Spring Authorization Server.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}
