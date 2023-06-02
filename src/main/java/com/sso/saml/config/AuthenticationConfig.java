package com.sso.saml.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationProvider;

import java.util.Arrays;

/**
 * @author jian.xiong
 * @title: AuthenticationConfig
 * @projectName toolbox
 * @description: TODO
 * @date 2022-12-12
 */
@ConditionalOnClass(SAMLConfig.class)
@Configuration
public class AuthenticationConfig {

    //普通Springseurity配置用户名密码登录权限
//    @Bean
//    public AuthenticationProvider authenticationProvider(DomainUserDetailsService domainUserDetailsService){
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setUserDetailsService(domainUserDetailsService);
//        return daoAuthenticationProvider;
//    }

    //配置saml登录权限，如果没有可以注释
//    @Bean
//    public AuthenticationManager samlAuthenticationManager(SAMLAuthenticationProvider samlAuthenticationProvider,AuthenticationProvider authenticationProvider) {
//        return new ProviderManager(Arrays.asList(authenticationProvider,samlAuthenticationProvider));
//    }

    //单独配置saml登录权限，如果没有可以注释
    @Bean
    public AuthenticationManager samlAuthenticationManager(SAMLAuthenticationProvider samlAuthenticationProvider) {
        return new ProviderManager(Arrays.asList(samlAuthenticationProvider));
    }
}
