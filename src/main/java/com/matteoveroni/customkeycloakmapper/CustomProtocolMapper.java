package com.matteoveroni.customkeycloakmapper;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.http.FormPartValue;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String CATEGORY = "Token Mapper";
    public static final String TYPE = "Custom Token Mapper";
    public static final String HELP_TEXT = "Adds a custom claim sent by the client in the form request";
    public static final String PROVIDER_ID = "custom-protocol-mapper";
    public static final String DEFAULT_CONFIG_PROPERTIES = "/keycloack-custom-mapper.properties";

    private static final Logger log = LoggerFactory.getLogger(CustomProtocolMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final List<String> customClaims = CustomClaimsPropertiesReader.loadCustomClaimsFromConfig(DEFAULT_CONFIG_PROPERTIES);

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return TYPE;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {

        MultivaluedMap<String, FormPartValue> multiPartFormParams = keycloakSession
                .getContext()
                .getHttpRequest()
                .getMultiPartFormParameters();

        log.debug("multiPartFormParams: {}", multiPartFormParams);

        if (multiPartFormParams != null) {
            for (String claimName : customClaims) {
                addClaimIfPresent(token, multiPartFormParams, claimName);
            }
        }
    }

    /**
     * Adds a claim to the token if the specified parameter is present in the multipart parameters.
     *
     * @param token                 The IDToken
     * @param multiPartFormParams   The multipart parameters of the request
     * @param paramName             The name of the parameter/claim to add
     */
    private void addClaimIfPresent(IDToken token, MultivaluedMap<String, FormPartValue> multiPartFormParams, String paramName) {
        if (multiPartFormParams.containsKey(paramName)) {
            List<FormPartValue> paramValues = multiPartFormParams.get(paramName);
            if (paramValues != null && !paramValues.isEmpty()) {
                FormPartValue claimValue = paramValues.getFirst();
                log.debug("add claim: {}", claimValue.asString());
                token.getOtherClaims().put(paramName, claimValue.asString());
            }
        }
    }
}
