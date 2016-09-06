package com.autoscout24.dotcms.authentication.api;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.JsonTokenExtractor;
import org.scribe.model.*;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

public class Auth02Api extends DefaultApi20 {

    private String hostname;
    private String connection;
    private String state;

    /**
     * Adds Auth0 specific configuration.
     *
     * Has to be called before the API is used. Sidesteps OAuthConfig since Auth0 needs extra configuration that
     * cannot be set in OAuthConfig.
     */
    public void configure(String hostname, String connection, String state)
    {
        this.hostname = hostname;
        this.connection = connection;
        this.state = state;
    }

    /**
     * @return the authorization URL pattern
     */
    private String authorizationUrl() {
        return "https://%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=%s&connection=%s&scope=%s";
    }

    @Override
    /* {@inheritDoc} */
    public String getAccessTokenEndpoint()
    {
        return "https://" + this.hostname + "/oauth/token";
    }

    @Override
    /* {@inheritDoc} */
    public String getAuthorizationUrl(OAuthConfig config)
    {
        Preconditions.checkValidUrl(config.getCallback(), "Must provide a valid url as callback.");
        return String.format(authorizationUrl(), this.hostname, config.getApiKey(), OAuthEncoder.encode(config.getCallback()), this.state, this.connection, OAuthEncoder.encode(config.getScope()));
    }

    @Override
    /* {@inheritDoc} */
    public AccessTokenExtractor getAccessTokenExtractor()
    {
        return new JsonTokenExtractor();
    }

    @Override
    /* {@inheritDoc} */
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    /* {@inheritDoc} */
    public OAuthService createService(OAuthConfig config) {
        return new Auth02Api.Auth0Api2Service(this, config);
    }

    /**
     * Implements OAuth service for Auth0.
     *
     * In constrast to other services, the access token has to be retrieved using POST request.
     */
    private class Auth0Api2Service extends OAuth20ServiceImpl {

        private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
        private static final String GRANT_TYPE = "grant_type";
        private DefaultApi20 api;
        private OAuthConfig config;

        Auth0Api2Service(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }

        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {
            OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
            request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
            request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
            request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
            request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
            request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
            request.addBodyParameter(OAuthConstants.SCOPE, config.getScope());
            Response response = request.send();

            return api.getAccessTokenExtractor().extract(response.getBody());
        }
    }
}
