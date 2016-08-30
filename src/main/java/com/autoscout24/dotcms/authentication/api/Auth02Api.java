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

    private final String hostname;

    public Auth02Api(String hostname)
    {
        this.hostname = hostname;
    }

    // TODO: Change connection parameter to Azure AD
    private String authorizationUrl() {
        return "https://" + this.hostname +  "/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=%s&connection=google-oauth2&scope=%s";
    }

    @Override
    public String getAccessTokenEndpoint()
    {
        return "https://" + this.hostname + "/oauth/token";
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config)
    {
        Preconditions.checkValidUrl(config.getCallback(), "Must provide a valid url as callback.");
        // TODO: Do we need the state parameter. According to the Auth0 documentation (https://auth0.com/docs/protocols),
        // it is necessary to avoid CSRF attacks. However, no other API implementation in dotCMS is using it.
        return String.format(authorizationUrl(), config.getApiKey(), OAuthEncoder.encode(config.getCallback()), "TODO", OAuthEncoder.encode(config.getScope()));
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor()
    {
        return new JsonTokenExtractor();
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new Auth02Api.Auth0Api2Service(this, config);
    }


    private class Auth0Api2Service extends OAuth20ServiceImpl {

        private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
        private static final String GRANT_TYPE = "grant_type";
        private DefaultApi20 api;
        private OAuthConfig config;

        public Auth0Api2Service(DefaultApi20 api, OAuthConfig config) {
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
