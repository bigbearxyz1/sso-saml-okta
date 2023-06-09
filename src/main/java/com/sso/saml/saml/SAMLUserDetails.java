package com.sso.saml.saml;

import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Default Implementation of {@link UserDetails} for Spring Boot Security SAML. This simple implementation hardly covers all security aspects since it's mostly
 * hardcoded. I.E. accounts are never locked, expired, or disabled, and always return the same granted authority "ROLE_USER". Consider implementing your own
 * {@link UserDetails} and {@link SAMLUserDetailsService}.
 */
public class SAMLUserDetails implements UserDetails {

    private SAMLCredential samlCredential;
    private Boolean rememberMe;

    public SAMLUserDetails(SAMLCredential samlCredential) {
        this.samlCredential = samlCredential;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return samlCredential.getNameID().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Boolean getRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(Boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    public String getAttribute(String name) {
        return samlCredential.getAttributeAsString(name);
    }

    public String[] getAttributeArray(String name) {
        return samlCredential.getAttributeAsStringArray(name);
    }

    public Map<String, String> getAttributes() {
        return samlCredential.getAttributes().stream()
                .collect(Collectors.toMap(Attribute::getName, this::getString));
    }

    private String getString(Attribute attribute) {
        String value = getValue(attribute);
        return value == null ? "" : value;
    }

    public Map<String, String[]> getAttributesArrays() {
        return samlCredential.getAttributes().stream()
                .collect(Collectors.toMap(Attribute::getName, this::getValueArray));
    }

    private String getValue(Attribute attribute) {
        return getAttribute(attribute.getName());
    }

    private String[] getValueArray(Attribute attribute) {
        return getAttributeArray(attribute.getName());
    }

    @Override
    public String toString() {
        return "SAMLUserDetails{" +
                "samlCredential=" + samlCredential +
                ", rememberMe=" + rememberMe +
                '}';
    }
}