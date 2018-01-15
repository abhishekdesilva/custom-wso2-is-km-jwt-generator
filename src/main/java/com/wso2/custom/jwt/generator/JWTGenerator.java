package com.wso2.custom.jwt.generator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.token.ClaimsRetriever;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.AbstractJWTGenerator;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.LinkedHashMap;
import java.util.Map;

public class JWTGenerator extends AbstractJWTGenerator{

    private static final Log log = LogFactory.getLog(JWTGenerator.class);


    @Override
    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext)
            throws APIManagementException {


        //generating expiring timestamp
        long currentTime = System.currentTimeMillis() ;
        long expireIn = currentTime + getTTL() * 1000;

        String dialect;
        ClaimsRetriever claimsRetriever = getClaimsRetriever();
        if (claimsRetriever != null) {
            dialect = claimsRetriever.getDialectURI(validationContext.getValidationInfoDTO().getEndUserName());
        } else {
            dialect = getDialectURI();
        }

        String subscriber = validationContext.getValidationInfoDTO().getSubscriber();
        String applicationName = validationContext.getValidationInfoDTO().getApplicationName();
        String applicationId = validationContext.getValidationInfoDTO().getApplicationId();
        String tier = validationContext.getValidationInfoDTO().getTier();
        String endUserName = validationContext.getValidationInfoDTO().getEndUserName();
        String keyType = validationContext.getValidationInfoDTO().getType();
        String userType = validationContext.getValidationInfoDTO().getUserType();
        String applicationTier = validationContext.getValidationInfoDTO().getApplicationTier();
        String enduserTenantId = String.valueOf(APIUtil.getTenantId(endUserName));
        String refreshToken = "";

        try {
            AccessTokenDO accessTokenDo = OAuth2Util.getAccessTokenDOfromTokenIdentifier(validationContext.getAccessToken());
            refreshToken = accessTokenDo.getRefreshToken();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while retrieving the OAuth2 refresh token");
        }


        Map<String, String> claims = new LinkedHashMap<String, String>(20);

        claims.put("iss", API_GATEWAY_ID);
        claims.put("exp", String.valueOf(expireIn));
        claims.put(dialect + "/subscriber", subscriber);
        claims.put(dialect + "/applicationid", applicationId);
        claims.put(dialect + "/applicationname", applicationName);
        claims.put(dialect + "/applicationtier", applicationTier);
        claims.put(dialect + "/apicontext", validationContext.getContext());
        claims.put(dialect + "/version", validationContext.getVersion());
        claims.put(dialect + "/tier", tier);
        claims.put(dialect + "/keytype", keyType);
        claims.put(dialect + "/usertype", userType);
        claims.put(dialect + "/enduser", APIUtil.getUserNameWithTenantSuffix(endUserName));
        claims.put(dialect + "/enduserTenantId", enduserTenantId);

        //Adding the OAuth access token
        claims.put("access_token", validationContext.getAccessToken());

        //Adding the OAuth refresh token
        claims.put("refresh_token", refreshToken);

        return claims;
    }

    @Override
    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext)
            throws APIManagementException {

        ClaimsRetriever claimsRetriever = getClaimsRetriever();
        if (claimsRetriever != null) {
            String tenantAwareUserName = validationContext.getValidationInfoDTO().getEndUserName();
            try {
                return claimsRetriever.getClaims(tenantAwareUserName);

            } catch (APIManagementException e) {
                log.error("Error while retrieving claims ", e);
            }
        }
        return null;
    }
}
