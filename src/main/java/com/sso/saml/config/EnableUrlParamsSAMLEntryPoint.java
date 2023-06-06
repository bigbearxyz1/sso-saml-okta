package com.sso.saml.config;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class EnableUrlParamsSAMLEntryPoint extends SAMLEntryPoint {
    public static final String RELAY_STATE = "RelayState";

    /**
     * @Author jian.xiong
     * @Description 自定义重定向参数
     * @Date 2023/6/6
     **/
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        try {
            SAMLMessageContext context = this.contextProvider.getLocalAndPeerEntity(request, response);
            //构建自定义重定向url--start
            String redirectUrl = request.getParameter(RELAY_STATE);
            context.setRelayState(redirectUrl);
            //构建自定义重定向url--end
            if (this.isECP(context)) {
                this.initializeECP(context, e);
            } else if (this.isDiscovery(context)) {
                this.initializeDiscovery(context);
            } else {
                this.initializeSSO(context, e);
            }

        } catch (SAMLException var5) {
            log.debug("Error initializing entry point", var5);
            throw new ServletException(var5);
        } catch (MetadataProviderException var6) {
            log.debug("Error initializing entry point", var6);
            throw new ServletException(var6);
        } catch (MessageEncodingException var7) {
            log.debug("Error initializing entry point", var7);
            throw new ServletException(var7);
        }
    }
}
