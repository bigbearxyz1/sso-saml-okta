package com.sso.saml.config;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLStatusException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.AbstractProfileBase;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.util.Assert;

import javax.xml.namespace.QName;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author jian.xiong
 * @title: CustomWebSSOProfileConsumerImpl
 * @projectName toolbox
 * @description: TODO
 * @date 2022-12-25
 */
public class CustomWebSSOProfileConsumerImpl extends AbstractProfileBase implements WebSSOProfileConsumer {

    private long maxAuthenticationAge = 7200L;
    private boolean includeAllAttributes = false;
    private boolean releaseDOM = true;

    public CustomWebSSOProfileConsumerImpl() {
    }

    public CustomWebSSOProfileConsumerImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    public String getProfileIdentifier() {
        return "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";
    }

    //idp调用本机saml/SSO路径以后，完成SAMLCredential对象构造
    public SAMLCredential processAuthenticationResponse(SAMLMessageContext context) throws SAMLException, SecurityException, ValidationException, DecryptionException {
        AuthnRequest request = null;
        SAMLObject message = context.getInboundSAMLMessage();
        if (!(message instanceof Response)) {
            throw new SAMLException("Message is not of a Response object type");
        } else {
            Response response = (Response)message;
            StatusCode statusCode = response.getStatus().getStatusCode();
            if (!"urn:oasis:names:tc:SAML:2.0:status:Success".equals(statusCode.getValue())) {
                StatusMessage statusMessage = response.getStatus().getStatusMessage();
                String statusMessageText = null;
                if (statusMessage != null) {
                    statusMessageText = statusMessage.getMessage();
                }

                String finalStatusCode;
                for(finalStatusCode = statusCode.getValue(); statusCode.getStatusCode() != null; statusCode = statusCode.getStatusCode()) {
                    finalStatusCode = statusCode.getStatusCode().getValue();
                }

                throw new SAMLStatusException(finalStatusCode, "Response has invalid status code " + finalStatusCode + ", status message is " + statusMessageText);
            } else {
                if (response.getSignature() != null && !context.isInboundSAMLMessageAuthenticated()) {
                    this.log.debug("Verifying Response signature");
                    this.verifySignature(response.getSignature(), context.getPeerEntityId(), context.getLocalTrustEngine());
                    context.setInboundSAMLMessageAuthenticated(true);
                }

                DateTime time = response.getIssueInstant();
                if (!SAMLUtil.isDateTimeSkewValid(this.getResponseSkew(), time)) {
                    throw new SAMLException("Response issue time is either too old or with date in the future, skew " + this.getResponseSkew() + ", time " + time);
                } else if (!context.getPeerExtendedMetadata().isSupportUnsolicitedResponse() && response.getInResponseTo() == null) {
                    throw new SAMLException("Reception of Unsolicited Response messages (without InResponseToField) is disabled");
                } else {
                    SAMLMessageStorage messageStorage = context.getMessageStorage();
                    if (messageStorage != null && response.getInResponseTo() != null) {
                        XMLObject xmlObject = messageStorage.retrieveMessage(response.getInResponseTo());
                        if (xmlObject == null) {
                            this.log.warn("InResponseToField of the Response doesn't correspond to sent message :{}",response.getInResponseTo());
//                            throw new SAMLException("InResponseToField of the Response doesn't correspond to sent message " + response.getInResponseTo());
                        }

                        if (!(xmlObject instanceof AuthnRequest)) {
                            this.log.warn("Sent request was of different type than the expected AuthnRequest :{}",response.getInResponseTo());
//                            throw new SAMLException("Sent request was of different type than the expected AuthnRequest " + response.getInResponseTo());
                        }

                        request = (AuthnRequest)xmlObject;
                    }

                    this.verifyEndpoint(context.getLocalEntityEndpoint(), response.getDestination());
                    if (request != null) {
                        AssertionConsumerService assertionConsumerService = (AssertionConsumerService)context.getLocalEntityEndpoint();
                        if (request.getAssertionConsumerServiceIndex() != null) {
                            if (!request.getAssertionConsumerServiceIndex().equals(assertionConsumerService.getIndex())) {
                                this.log.info("Response was received at a different endpoint index than was requested");
                            }
                        } else {
                            String requestedResponseURL = request.getAssertionConsumerServiceURL();
                            String requestedBinding = request.getProtocolBinding();
                            if (requestedResponseURL != null) {
                                String responseLocation;
                                if (assertionConsumerService.getResponseLocation() != null) {
                                    responseLocation = assertionConsumerService.getResponseLocation();
                                } else {
                                    responseLocation = assertionConsumerService.getLocation();
                                }

                                if (!requestedResponseURL.equals(responseLocation)) {
                                    this.log.info("Response was received at a different endpoint URL {} than was requested {}", responseLocation, requestedResponseURL);
                                }
                            }

                            if (requestedBinding != null && !requestedBinding.equals(context.getInboundSAMLBinding())) {
                                this.log.info("Response was received using a different binding {} than was requested {}", context.getInboundSAMLBinding(), requestedBinding);
                            }
                        }
                    }

                    if (response.getIssuer() != null) {
                        this.log.debug("Verifying issuer of the Response");
                        Issuer issuer = response.getIssuer();
                        this.verifyIssuer(issuer, context);
                    }

                    Assertion subjectAssertion = null;
                    List<Attribute> attributes = new ArrayList();
                    List<Assertion> assertionList = response.getAssertions();
                    Iterator var12;
                    if (response.getEncryptedAssertions().size() > 0) {
                        assertionList = new ArrayList(response.getAssertions().size() + response.getEncryptedAssertions().size());
                        ((List)assertionList).addAll(response.getAssertions());
                        List<EncryptedAssertion> encryptedAssertionList = response.getEncryptedAssertions();
                        var12 = encryptedAssertionList.iterator();

                        while(var12.hasNext()) {
                            EncryptedAssertion ea = (EncryptedAssertion)var12.next();

                            try {
                                Assert.notNull(context.getLocalDecrypter(), "Can't decrypt Assertion, no decrypter is set in the context");
                                this.log.debug("Decrypting assertion");
                                Assertion decryptedAssertion = context.getLocalDecrypter().decrypt(ea);
                                ((List)assertionList).add(decryptedAssertion);
                            } catch (DecryptionException var19) {
                                this.log.debug("Decryption of received assertion failed, assertion will be skipped", var19);
                            }
                        }
                    }

                    Exception lastError = null;
                    var12 = ((List)assertionList).iterator();

                    Assertion assertion;
                    while(var12.hasNext()) {
                        assertion = (Assertion)var12.next();
                        if (assertion.getAuthnStatements().size() > 0) {
                            try {
                                this.verifyAssertion(assertion, request, context);
                                subjectAssertion = assertion;
                                this.log.debug("Validation of authentication statement in assertion {} was successful", assertion.getID());
                                break;
                            } catch (Exception var20) {
                                this.log.debug("Validation of authentication statement in assertion failed, skipping", var20);
                                lastError = var20;
                            }
                        } else {
                            this.log.debug("Assertion {} did not contain any authentication statements, skipping", assertion.getID());
                        }
                    }

                    if (subjectAssertion == null) {
                        throw new SAMLException("Response doesn't have any valid assertion which would pass subject validation", lastError);
                    } else {
                        var12 = ((List)assertionList).iterator();

                        while(true) {
                            do {
                                if (!var12.hasNext()) {
                                    NameID nameId = (NameID)context.getSubjectNameIdentifier();
                                    if (nameId == null) {
                                        throw new SAMLException("NameID element must be present as part of the Subject in the Response message, please enable it in the IDP configuration");
                                    }

                                    Serializable additionalData = this.processAdditionalData(context);
                                    if (this.isReleaseDOM()) {
                                        subjectAssertion.releaseDOM();
                                        subjectAssertion.releaseChildrenDOM(true);
                                    }

                                    return new SAMLCredential(nameId, subjectAssertion, context.getPeerEntityMetadata().getEntityID(), context.getRelayState(), attributes, context.getLocalEntityId(), additionalData);
                                }

                                assertion = (Assertion)var12.next();
                            } while(assertion != subjectAssertion && !this.isIncludeAllAttributes());

                            Iterator var34 = assertion.getAttributeStatements().iterator();

                            while(var34.hasNext()) {
                                AttributeStatement attStatement = (AttributeStatement)var34.next();
                                Iterator var16 = attStatement.getAttributes().iterator();

                                while(var16.hasNext()) {
                                    Attribute att = (Attribute)var16.next();
                                    this.log.debug("Including attribute {} from assertion {}", att.getName(), assertion.getID());
                                    attributes.add(att);
                                }

                                var16 = attStatement.getEncryptedAttributes().iterator();

                                while(var16.hasNext()) {
                                    EncryptedAttribute att = (EncryptedAttribute)var16.next();
                                    Assert.notNull(context.getLocalDecrypter(), "Can't decrypt Attribute, no decrypter is set in the context");
                                    Attribute decryptedAttribute = context.getLocalDecrypter().decrypt(att);
                                    this.log.debug("Including decrypted attribute {} from assertion {}", decryptedAttribute.getName(), assertion.getID());
                                    attributes.add(decryptedAttribute);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    protected Serializable processAdditionalData(SAMLMessageContext context) throws SAMLException {
        return null;
    }

    protected void verifyAssertion(Assertion assertion, AuthnRequest request, SAMLMessageContext context) throws AuthenticationException, SAMLException, SecurityException, ValidationException, DecryptionException {
        if (!SAMLUtil.isDateTimeSkewValid(this.getResponseSkew(), (long)this.getMaxAssertionTime(), assertion.getIssueInstant())) {
            throw new SAMLException("Assertion is too old to be used, value can be customized by setting maxAssertionTime value " + assertion.getIssueInstant());
        } else {
            this.verifyIssuer(assertion.getIssuer(), context);
            this.verifyAssertionSignature(assertion.getSignature(), context);
            if (assertion.getSubject() == null) {
                throw new SAMLException("Assertion does not contain subject and is discarded");
            } else {
                this.verifySubject(assertion.getSubject(), request, context);
                if (assertion.getAuthnStatements().size() > 0) {
                    this.verifyAssertionConditions(assertion.getConditions(), context, true);
                    Iterator var4 = assertion.getAuthnStatements().iterator();

                    while(var4.hasNext()) {
                        AuthnStatement statement = (AuthnStatement)var4.next();
                        if (request != null) {
                            this.verifyAuthenticationStatement(statement, request.getRequestedAuthnContext(), context);
                        } else {
                            this.verifyAuthenticationStatement(statement, (RequestedAuthnContext)null, context);
                        }
                    }
                } else {
                    this.verifyAssertionConditions(assertion.getConditions(), context, false);
                }

            }
        }
    }

    protected void verifySubject(Subject subject, AuthnRequest request, SAMLMessageContext context) throws SAMLException, DecryptionException {
        Iterator var4 = subject.getSubjectConfirmations().iterator();

        label77:
        while(true) {
            while(true) {
                SubjectConfirmationData data;
                label68:
                while(true) {
                    while(true) {
                        while(true) {
                            while(true) {
                                while(true) {
                                    SubjectConfirmation confirmation;
                                    do {
                                        if (!var4.hasNext()) {
                                            throw new SAMLException("Assertion invalidated by subject confirmation - can't be confirmed by the bearer method");
                                        }

                                        confirmation = (SubjectConfirmation)var4.next();
                                    } while(!"urn:oasis:names:tc:SAML:2.0:cm:bearer".equals(confirmation.getMethod()));

                                    this.log.debug("Processing Bearer subject confirmation");
                                    data = confirmation.getSubjectConfirmationData();
                                    if (data != null) {
                                        if (data.getNotBefore() == null) {
                                            if (data.getNotOnOrAfter() != null) {
                                                if (!data.getNotOnOrAfter().plusSeconds(this.getResponseSkew()).isBeforeNow()) {
                                                    if (request == null) {
                                                        break label68;
                                                    }

                                                    if (data.getInResponseTo() == null) {
                                                        this.log.debug("Bearer SubjectConfirmation invalidated by missing inResponseTo field");
                                                    } else {
                                                        if (data.getInResponseTo().equals(request.getID())) {
                                                            break label68;
                                                        }

                                                        this.log.debug("Bearer SubjectConfirmation invalidated by invalid in response to");
                                                    }
                                                } else {
                                                    this.log.debug("Bearer SubjectConfirmation invalidated by notOnOrAfter");
                                                }
                                            } else {
                                                this.log.debug("Bearer SubjectConfirmation invalidated by missing notOnOrAfter");
                                            }
                                        } else {
                                            this.log.debug("Bearer SubjectConfirmation invalidated by not before which is forbidden");
                                        }
                                    } else {
                                        this.log.debug("Bearer SubjectConfirmation invalidated by missing confirmation data");
                                    }
                                }
                            }
                        }
                    }
                }

                if (data.getRecipient() != null) {
                    try {
                        this.verifyEndpoint(context.getLocalEntityEndpoint(), data.getRecipient());
                        break label77;
                    } catch (SAMLException var8) {
                        this.log.debug("Bearer SubjectConfirmation invalidated by recipient assertion consumer URL, found {}", data.getRecipient());
                    }
                } else {
                    this.log.debug("Bearer SubjectConfirmation invalidated by missing recipient");
                }
            }
        }

        NameID nameID;
        if (subject.getEncryptedID() != null) {
            Assert.notNull(context.getLocalDecrypter(), "Can't decrypt NameID, no decrypter is set in the context");
            nameID = (NameID)context.getLocalDecrypter().decrypt(subject.getEncryptedID());
        } else {
            nameID = subject.getNameID();
        }

        context.setSubjectNameIdentifier(nameID);
    }

    protected void verifyAssertionSignature(Signature signature, SAMLMessageContext context) throws SAMLException, SecurityException, ValidationException {
        SPSSODescriptor roleMetadata = (SPSSODescriptor)context.getLocalEntityRoleMetadata();
        boolean wantSigned = roleMetadata.getWantAssertionsSigned();
        if (signature != null) {
            this.verifySignature(signature, context.getPeerEntityMetadata().getEntityID(), context.getLocalTrustEngine());
        } else if (wantSigned && !context.isInboundSAMLMessageAuthenticated()) {
            throw new SAMLException("Metadata includes wantAssertionSigned, but neither Response nor included Assertion is signed");
        }

    }

    protected void verifyAssertionConditions(Conditions conditions, SAMLMessageContext context, boolean audienceRequired) throws SAMLException {
        if (!audienceRequired || conditions != null && conditions.getAudienceRestrictions().size() != 0) {
            if (conditions != null) {
                if (conditions.getNotBefore() != null && conditions.getNotBefore().minusSeconds(this.getResponseSkew()).isAfterNow()) {
                    throw new SAMLException("Assertion is not yet valid, invalidated by condition notBefore " + conditions.getNotBefore());
                } else if (conditions.getNotOnOrAfter() != null && conditions.getNotOnOrAfter().plusSeconds(this.getResponseSkew()).isBeforeNow()) {
                    throw new SAMLException("Assertion is no longer valid, invalidated by condition notOnOrAfter " + conditions.getNotOnOrAfter());
                } else {
                    List<Condition> notUnderstoodConditions = new LinkedList();
                    Iterator var5 = conditions.getConditions().iterator();

                    while(var5.hasNext()) {
                        Condition condition = (Condition)var5.next();
                        QName conditionQName = condition.getElementQName();
                        if (conditionQName.equals(AudienceRestriction.DEFAULT_ELEMENT_NAME)) {
                            this.verifyAudience(context, conditions.getAudienceRestrictions());
                        } else {
                            if (conditionQName.equals(OneTimeUse.DEFAULT_ELEMENT_NAME)) {
                                throw new SAMLException("System cannot honor OneTimeUse condition of the Assertion for WebSSO");
                            }

                            if (conditionQName.equals(ProxyRestriction.DEFAULT_ELEMENT_NAME)) {
                                ProxyRestriction restriction = (ProxyRestriction)condition;
                                this.log.debug("Honoring ProxyRestriction with count {}, system does not issue assertions to 3rd parties", restriction.getProxyCount());
                            } else {
                                this.log.debug("Condition {} is not understood", condition);
                                notUnderstoodConditions.add(condition);
                            }
                        }
                    }

                    this.verifyConditions(context, notUnderstoodConditions);
                }
            }
        } else {
            throw new SAMLException("Assertion invalidated by missing Audience Restriction");
        }
    }

    protected void verifyAudience(SAMLMessageContext context, List<AudienceRestriction> audienceRestrictions) throws SAMLException {
        Iterator var3 = audienceRestrictions.iterator();

        label25:
        while(var3.hasNext()) {
            AudienceRestriction rest = (AudienceRestriction)var3.next();
            if (rest.getAudiences().size() == 0) {
                throw new SAMLException("No audit audience specified for the assertion");
            }

            Iterator var5 = rest.getAudiences().iterator();

            while(var5.hasNext()) {
                Audience aud = (Audience)var5.next();
                if (context.getLocalEntityId().equals(aud.getAudienceURI())) {
                    continue label25;
                }
            }

            throw new SAMLException("Local entity is not the intended audience of the assertion in at least one AudienceRestriction");
        }

    }

    protected void verifyConditions(SAMLMessageContext context, List<Condition> conditions) throws SAMLException {
        if (conditions != null && conditions.size() > 0) {
            throw new SAMLException("Assertion contains conditions which are not understood");
        }
    }

    protected void verifyAuthenticationStatement(AuthnStatement auth, RequestedAuthnContext requestedAuthnContext, SAMLMessageContext context) throws AuthenticationException {
        if (!SAMLUtil.isDateTimeSkewValid(this.getResponseSkew(), this.getMaxAuthenticationAge(), auth.getAuthnInstant())) {
            throw new CredentialsExpiredException("Authentication statement is too old to be used with value " + auth.getAuthnInstant());
        } else if (auth.getSessionNotOnOrAfter() != null && auth.getSessionNotOnOrAfter().isBeforeNow()) {
            throw new CredentialsExpiredException("Authentication session is not valid on or after " + auth.getSessionNotOnOrAfter());
        } else {
            this.verifyAuthnContext(requestedAuthnContext, auth.getAuthnContext(), context);
        }
    }

    protected void verifyAuthnContext(RequestedAuthnContext requestedAuthnContext, AuthnContext receivedContext, SAMLMessageContext context) throws InsufficientAuthenticationException {
        this.log.debug("Verifying received AuthnContext {} against requested {}", receivedContext, requestedAuthnContext);
        if (requestedAuthnContext != null && AuthnContextComparisonTypeEnumeration.EXACT.equals(requestedAuthnContext.getComparison())) {
            String classRef = null;
            String declRef = null;
            if (receivedContext.getAuthnContextClassRef() != null) {
                classRef = receivedContext.getAuthnContextClassRef().getAuthnContextClassRef();
            }

            Iterator var6;
            if (requestedAuthnContext.getAuthnContextClassRefs() != null) {
                var6 = requestedAuthnContext.getAuthnContextClassRefs().iterator();

                while(var6.hasNext()) {
                    AuthnContextClassRef classRefRequested = (AuthnContextClassRef)var6.next();
                    if (classRefRequested.getAuthnContextClassRef().equals(classRef)) {
                        this.log.debug("AuthContext matched with value {}", classRef);
                        return;
                    }
                }
            }

            if (receivedContext.getAuthnContextDeclRef() != null) {
                declRef = receivedContext.getAuthnContextDeclRef().getAuthnContextDeclRef();
            }

            if (requestedAuthnContext.getAuthnContextDeclRefs() != null) {
                var6 = requestedAuthnContext.getAuthnContextDeclRefs().iterator();

                while(var6.hasNext()) {
                    AuthnContextDeclRef declRefRequested = (AuthnContextDeclRef)var6.next();
                    if (declRefRequested.getAuthnContextDeclRef().equals(declRef)) {
                        this.log.debug("AuthContext matched with value {}", declRef);
                        return;
                    }
                }
            }

            throw new InsufficientAuthenticationException("Response doesn't contain any of the requested authentication context class or declaration references");
        }
    }

    public long getMaxAuthenticationAge() {
        return this.maxAuthenticationAge;
    }

    public void setMaxAuthenticationAge(long maxAuthenticationAge) {
        this.maxAuthenticationAge = maxAuthenticationAge;
    }

    public boolean isIncludeAllAttributes() {
        return this.includeAllAttributes;
    }

    public void setIncludeAllAttributes(boolean includeAllAttributes) {
        this.includeAllAttributes = includeAllAttributes;
    }

    public boolean isReleaseDOM() {
        return this.releaseDOM;
    }

    public void setReleaseDOM(boolean releaseDOM) {
        this.releaseDOM = releaseDOM;
    }
}
