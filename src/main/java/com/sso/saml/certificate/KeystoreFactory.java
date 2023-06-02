package com.sso.saml.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StreamUtils;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

public class KeystoreFactory {

    private static final String FLAG_START = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String FLAG_END = "-----END RSA PRIVATE KEY-----";

    private static final String DEFAULT_KEY_ALIAS = "defaultKeyAlias";
    private static final char[] DEFAULT_KEY_STORE_PASS = "defaultKeyStorePass".toCharArray();

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    /**
     * 获取 JKSKeyManager。
     *
     * @param publicKeyCertLocation  公钥证书所在位置
     * @param privateKeyCertLocation 私钥证书所在位置
     * @return JKSKeyManager
     */
    public JKSKeyManager getJKSKeyManager(String publicKeyCertLocation, String privateKeyCertLocation) throws Exception {
        KeyStore keystore = createEmptyKeystore();
        final Certificate cert = loadCert(publicKeyCertLocation);
        PrivateKey privateKey = loadPrivateKey(privateKeyCertLocation);
        addKeyToKeystore(keystore, cert, privateKey, DEFAULT_KEY_ALIAS, DEFAULT_KEY_STORE_PASS);
        return createJKSKeyManager(keystore,
                Collections.singletonMap(DEFAULT_KEY_ALIAS, new String(DEFAULT_KEY_STORE_PASS)),
                DEFAULT_KEY_ALIAS);
    }

    /**
     * 获取 JKSKeyManager
     *
     * @param keyStoreLocation jks 所在位置，该 jks 必须只包 1 把私钥
     * @param keyStorePassword jks 的密码
     * @param keyPassword      私钥的密码
     * @return JKSKeyManager
     */
    public JKSKeyManager getJKSKeyManager(String keyStoreLocation, char[] keyStorePassword, char[] keyPassword) throws Exception {
        final File keyStoreFile = ResourceUtils.getFile(keyStoreLocation);
        final KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStoreFile), keyStorePassword);

        final Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                final Key key = ks.getKey(alias, keyPassword);
                if (key == null) {
                    throw new IllegalStateException("Can't get private key in keystore with the given key password.");
                }
                return createJKSKeyManager(ks, Collections.singletonMap(alias, new String(keyPassword)), alias);
            }
        }
        throw new IllegalStateException("Can't find any private key in keystore " + keyStoreLocation);
    }

    public void addKeyToKeystore(KeyStore keyStore, Certificate cert, PrivateKey privateKey, String alias, char[] password) throws Exception {
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password);
        Certificate[] certificateChain = {cert};
        keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
    }

    public KeyStore createEmptyKeystore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "".toCharArray());
        return keyStore;
    }

    public JKSKeyManager createJKSKeyManager(KeyStore keyStore, Map<String, String> passwords, String defaultKey) {
        return new JKSKeyManager(keyStore, passwords, defaultKey);
    }

    public Certificate loadCert(String certLocation) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return cf.generateCertificate(getClass().getClassLoader().getResourceAsStream(certLocation));
    }

    public PrivateKey loadPrivateKey(String privateKeyLocation) throws Exception {
        byte[] keyBytes = StreamUtils.copyToByteArray(getClass().getClassLoader().getResourceAsStream(privateKeyLocation));
        //私钥既可以是localhost.key,也可以是localhost.key.cert
        if (privateKeyLocation.endsWith(".key")) {
            final String pvKey = new String(keyBytes);
            final String base64 = pvKey.replaceAll("\r", "").replaceAll("\n", "")
                    .replaceAll(FLAG_START, "").replaceAll(FLAG_END, "");
            keyBytes = Base64.getDecoder().decode(base64);
        }
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BC);
        return keyFactory.generatePrivate(privateKeySpec);
    }

}