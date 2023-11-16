/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.google;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONValue;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.checkerframework.checker.units.qual.C;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.registration.RegistrationStepExecutor;
import org.wso2.carbon.identity.user.registration.config.RegistrationStepExecutorConfig;
import org.wso2.carbon.identity.user.registration.exception.RegistrationFrameworkException;
import org.wso2.carbon.identity.user.registration.model.RegistrationContext;
import org.wso2.carbon.identity.user.registration.model.RegistrationRequest;
import org.wso2.carbon.identity.user.registration.model.RegistrationRequestedUser;
import org.wso2.carbon.identity.user.registration.model.response.ExecutorMetadata;
import org.wso2.carbon.identity.user.registration.model.response.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.model.response.Message;
import org.wso2.carbon.identity.user.registration.model.response.NextStepResponse;
import org.wso2.carbon.identity.user.registration.model.response.RequiredParam;
import org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants;
import org.wso2.carbon.identity.user.registration.util.RegistrationFrameworkUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.Claim.NONCE;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.COMPLETE;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.INCOMPLETE;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.NOT_STARTED;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.USER_INPUT_REQUIRED;

/**
 * Google Registration Executor.
 */
public class GoogleRegistrationExecutor extends GoogleOAuth2Authenticator implements RegistrationStepExecutor {

    private static GoogleRegistrationExecutor instance = new GoogleRegistrationExecutor();

    private static final Log LOG = LogFactory.getLog(GoogleRegistrationExecutor.class);
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String ID_TOKEN = "idToken";
    private static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp"};

    public static GoogleRegistrationExecutor getInstance() {

        return instance;
    }

    @Override
    public String getName() {

        return "GoogleRegistrationExecutor";
    }

    @Override
    public RegistrationFlowConstants.RegistrationExecutorBindingType getBindingType() throws RegistrationFrameworkException {

        return RegistrationFlowConstants.RegistrationExecutorBindingType.AUTHENTICATOR;
    }

    @Override
    public String getBoundIdentifier() throws RegistrationFrameworkException {

        return GoogleOAuth2AuthenticationConstant.GOOGLE_CONNECTOR_NAME;
    }

    @Override
    public String getExecutorType() throws RegistrationFrameworkException {

        return null;
    }

    @Override
    public RegistrationFlowConstants.StepStatus execute(RegistrationRequest registrationRequest,
                                                        RegistrationContext registrationContext,
                                                        NextStepResponse nextStepResponse,
                                                        RegistrationStepExecutorConfig registrationStepExecutorConfig) throws RegistrationFrameworkException {

        RegistrationFlowConstants.StepStatus stepStatus = registrationContext.getCurrentStepStatus();
        Map<String, String> authenticatorProperties = registrationStepExecutorConfig.getAuthenticatorProperties();

        if (stepStatus == NOT_STARTED) {
            initiateGoogleRegistration(registrationStepExecutorConfig, registrationContext, nextStepResponse, authenticatorProperties);
            return USER_INPUT_REQUIRED;
        }
        if (stepStatus == USER_INPUT_REQUIRED) {
            processGoogleRegistration(registrationContext,registrationRequest,authenticatorProperties);
            return COMPLETE;
        }
        return INCOMPLETE;
    }

    @Override
    public List<RequiredParam> getRequiredParams() {

        return null;
    }

    private void initiateGoogleRegistration(RegistrationStepExecutorConfig config, RegistrationContext context,
                                            NextStepResponse response, Map<String, String> authenticatorProperties) throws RegistrationFrameworkException {

        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        String scope = getScope(null, authenticatorProperties);
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String callbackurl = getCallbackUrl(authenticatorProperties);
        String state = getStateParameter(context, authenticatorProperties);
        String nonce = UUID.randomUUID().toString();

        OAuthClientRequest oAuthClientRequest;

        try {
            oAuthClientRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                    .setClientId(clientId)
                    .setRedirectURI(callbackurl)
                    .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                    .setState(state)
                    .setParameter(NONCE, nonce)
                    .setScope(scope)
                    .buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw new RegistrationFrameworkException("Error while building OAuthClientRequest", e);
        }

        Map <String, String> paramMap = new HashMap<>();
        paramMap.put("redirectUrl", oAuthClientRequest.getLocationUri());

        List<RequiredParam> params = new ArrayList<>();

        RequiredParam accessToken = new RequiredParam();
        accessToken.setName(ACCESS_TOKEN);
        accessToken.setConfidential(false);
        accessToken.setMandatory(true);
        accessToken.setDataType(RegistrationFlowConstants.DataType.STRING);
        accessToken.setOrder(1);
        accessToken.setI18nKey("access.token");
        params.add(accessToken);

        RequiredParam idToken = new RequiredParam();
        idToken.setName(ID_TOKEN);
        idToken.setConfidential(false);
        idToken.setMandatory(true);
        idToken.setDataType(RegistrationFlowConstants.DataType.STRING);
        idToken.setOrder(2);
        idToken.setI18nKey("id.token");
        params.add(idToken);

        Message message = new Message();
        message.setMessage("Continue with Google.");
        message.setType(RegistrationFlowConstants.MessageType.INFO);

        updateResponse(response, config, params, message, paramMap);

    }

    private void processGoogleRegistration(RegistrationContext context, RegistrationRequest request,
                                           Map<String, String> authenticatorProperties) throws RegistrationFrameworkException {

        Map<String, String> inputs = request.getInputs();

        if (inputs.get(ACCESS_TOKEN) == null) {
            throw new RegistrationFrameworkException("Access token is expected.");
        }
        if (inputs.get(ID_TOKEN) == null) {
            throw new RegistrationFrameworkException("ID token is expected.");
        }

        String idToken = inputs.get(ID_TOKEN);
        String accessToken = inputs.get(ACCESS_TOKEN);

        Map<ClaimMapping, String> claimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        Map<String, String> remoteClaims = new HashMap<>();

        if (StringUtils.isNotBlank(idToken)) {
            jwtAttributeMap = getIdTokenClaims(idToken);
        }
        jwtAttributeMap.entrySet().stream()
                .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                .forEach(entry -> buildClaimList(remoteClaims, entry, null));

        ClaimMapping[] claimMappings = new ClaimMapping[0];
        Map<String, String> userClaimList =
                RegistrationFrameworkUtils.convertClaimsFromIdpToLocalClaims(context.getTenantDomain(), remoteClaims,
                claimMappings, getClaimDialectURI());
        updateUserDetails(context, userClaimList);
    }
    private void updateResponse(NextStepResponse response, RegistrationStepExecutorConfig config,
                                List<RequiredParam> params, Message message, Map<String, String> additionalData) {

        ExecutorResponse executorResponse = new ExecutorResponse();
        executorResponse.setName(config.getName());
        executorResponse.setExecutorName(this.getName());
        executorResponse.setId(config.getId());

        ExecutorMetadata metadata = new ExecutorMetadata();
        metadata.setI18nKey("executor.googleRegistrationExecutor");
        metadata.setPromptType(RegistrationFlowConstants.PromptType.REDIRECTION_PROMPT);
        metadata.setRequiredParams(params);
        metadata.setAdditionalData(additionalData);
        executorResponse.setMetadata(metadata);

        response.addExecutor(executorResponse);
        response.addMessage(message);
    }

    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        String callbackUrl = authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        if (StringUtils.isBlank(callbackUrl)) {
            try {
                callbackUrl = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                        .getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
            }
        }
        return callbackUrl;
    }

    private String getStateParameter(RegistrationContext context, Map<String, String> authenticatorProperties) {

        return context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
    }

    private Map<String, Object> getIdTokenClaims(String idToken) {

        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getAuthenticatedUserId(RegistrationContext context, Map<String, Object> idTokenClaims) throws RegistrationFrameworkException {

        String authenticatedUserId = null;
        if (isUsernameAlreadyDefined(context)) {
            authenticatedUserId = context.getRegisteringUser().getUsername();
        } else {
            // TODO: 2023-11-09 This should be updated to check the IdP configs and get the claim uri.
            Object subject = idTokenClaims.get("http://wso2.org/claims/username");
            if (subject instanceof String) {
                authenticatedUserId = (String) subject;
            } else if (subject != null) {
                throw new RegistrationFrameworkException("Unable to map subject claim (non-String type): " + subject);
            }
        }

        if (authenticatedUserId == null) {
            throw new RegistrationFrameworkException( "User id not found in the id_token sent by federated IDP.");
        }
        return authenticatedUserId;
    }

    protected Map<ClaimMapping, String> getSubjectAttributes(String token,
                                                             Map<String, String> authenticatorProperties) {

        // TODO : Implement this method to call the userinfo endpoint of google and get the user claims.
        return null;
    }

    private boolean isUsernameAlreadyDefined(RegistrationContext context) {

        return context.getRegisteringUser() != null && context.getRegisteringUser().getUsername() != null;

    }

    private void buildClaimList(Map<String, String> claims, Map.Entry<String, Object> entry, String separator) {

        String claimValue = null;
        String claimUri   = "";
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        try {
            JSONArray jsonArray = (JSONArray) JSONValue.parseWithException(entry.getValue().toString());
            if (jsonArray != null && jsonArray.size() > 0) {
                Iterator attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = attributeIterator.next().toString();
                    } else {
                        claimValue = claimValue + separator + attributeIterator.next().toString();
                    }
                }

            }
        } catch (Exception e) {
            claimValue = entry.getValue().toString();
        }
        String claimDialectUri = getClaimDialectURI();
        if (super.getClaimDialectURI() != null && !super.getClaimDialectURI().equals(claimDialectUri)) {
            claimUri = claimDialectUri + "/";
        }

        claimUri += entry.getKey();
        claims.put(claimUri, claimValue);
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + claimUri + " <> " + claimUri + " : " + claimValue);
        }
    }

    private void updateUserDetails(RegistrationContext context, Map<String, String> claims) throws RegistrationFrameworkException {

        if (context.getRegisteringUser() == null) {
            context.setRegisteringUser(new RegistrationRequestedUser());
        }
        RegistrationRequestedUser user = context.getRegisteringUser();

        if (user.getUsername() == null) {
            if (claims.get("http://wso2.org/claims/username") != null) {
                user.setUsername(claims.get("http://wso2.org/claims/username"));
            } else if (claims.get("http://wso2.org/claims/emailaddress") != null) {
                user.setUsername(claims.get("http://wso2.org/claims/emailaddress"));
            } else {
                throw new RegistrationFrameworkException("Cannot resolve the user");
            }
        }
        user.getClaims().putAll(claims);
    }
}
