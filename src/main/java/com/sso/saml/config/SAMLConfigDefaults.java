package com.sso.saml.config;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.websso.*;

import java.util.List;

@Configuration
public class SAMLConfigDefaults {
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        CustomWebSSOProfileConsumerImpl webSSOProfileConsumer = new CustomWebSSOProfileConsumerImpl();
        webSSOProfileConsumer.setResponseSkew(600);
        webSSOProfileConsumer.setMaxAssertionTime(3000);
        return webSSOProfileConsumer;
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        WebSSOProfileConsumerHoKImpl webSSOProfileConsumerHoK = new WebSSOProfileConsumerHoKImpl();
        return webSSOProfileConsumerHoK;
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    @Bean
    public WebSSOProfileECPImpl ecpProfile() {
        return new WebSSOProfileECPImpl();
    }

    @Bean
    public WebSSOProfileHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileHoKImpl();
    }

    @Bean
    public SingleLogoutProfile logoutProfile() {
        return new SingleLogoutProfileImpl();
    }

    // 配置 IDP 元数据的 CachingMetadataManager
    @Bean
    public CachingMetadataManager metadataManager(List<MetadataProvider> metadataProviders) throws MetadataProviderException {
        return new CachingMetadataManager(metadataProviders);
    }
}