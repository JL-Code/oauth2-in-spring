package com.example.resource.demoresource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 资源服务器安全设置
 * <p>创建时间: 2023/8/27 </p>
 *
 * @author <a href="mailto:jiangliu0316@dingtalk.com" rel="nofollow">蒋勇</a>
 */
@EnableWebSecurity
@Configuration
public class ResourceServerConfig {

    /**
     * 跨域设置
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://localhost:4200");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // @formatter:off
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/hello/**").permitAll()
                .requestMatchers("/messages/**").authenticated()
        )
        .cors(Customizer.withDefaults())
        .oauth2ResourceServer(oauth2ResourceServer -> {
            // Add BearerTokenAuthenticationFilter 支持从 JWT 中恢复认证信息。
            oauth2ResourceServer.jwt(Customizer.withDefaults());
        });
        return http.build();
    }
    // @formatter:on
}
