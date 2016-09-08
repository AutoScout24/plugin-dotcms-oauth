/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have
 * chosen to have their login information remembered.
 * Creates a valid WebSession object and
 * passes it a contact to use to fill its information
 *
 */
package com.autoscout24.dotcms.authentication;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.autoscout24.dotcms.authentication.api.Auth02Api;
import com.autoscout24.dotcms.authentication.util.UserHelper;
import com.dotcms.repackage.javax.xml.bind.DatatypeConverter;
import com.dotcms.repackage.org.apache.commons.httpclient.HttpStatus;
import com.dotmarketing.util.json.JSONException;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.autoscout24.dotcms.authentication.util.OAuthPropertyBundle;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.cms.login.factories.LoginFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.json.JSONObject;
import com.dotmarketing.viewtools.JSONTool;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;
import org.scribe.utils.OAuthEncoder;

public class OAuth2Servlet extends HttpServlet {

	private static final long serialVersionUID = -7036009330382977246L;
	
	public void destroy() {

	}

	public OAuth2Servlet() {
	}

	private static String CALLBACK_URL;

	private String getState(String sessionId)
	{
		try {
			// Be careful. These classes are not thread-safe.
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			String salt = "4asd%8dqweAIds(4f";
			return  OAuthEncoder.encode(DatatypeConverter.printBase64Binary(messageDigest.digest((sessionId + salt).getBytes("UTF-8"))));
		} catch (Exception e) {
			throw new RuntimeException("Unable to get messageDigest", e);
		}
	}

	@Override
	public void service(ServletRequest req, ServletResponse res) throws IOException, ServletException {

		HttpServletResponse response = (HttpServletResponse) res;
		HttpServletRequest request = (HttpServletRequest) req;
		HttpSession session = request.getSession(true);
		String path = request.getRequestURI();

		String callbackHost = request.getScheme() + "://" + ((request.getServerPort() == 80 || request.getServerPort() == 443) ?
						request.getServerName() : request.getServerName()+":"+request.getServerPort());

		User user = getUserFromSession(request, session);

		// if the user is already logged in
		if (user != null) {
			Logger.error(this.getClass(), "Already logged in, redirecting home");
			response.reset();
			response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			response.setHeader("Location", "/?already-logged-in");
			return;
		}

		String state = getState(session.getId());
		OAuthService service = createOAuthService(callbackHost, state);

		if (path.contains(CALLBACK_URL)) {
            processAuth0Callback(response, request, session, callbackHost, state, service);
        } else {
			redirectToAuth0ForAuthentication(request, response, service);
		}

	}

	/**
	 * Processes the callback from Auth0.
	 *
	 * This is the second step, after the user has authenticated at Auth0. The callback URL contains an access token
	 * that is used by this function to retrieve the user data. If the user already exists in dotCMS, this user is
	 * logged in, otherwise a new user is created.
	 *
	 * On each login, the user groups are synchronized between Auth0 and dotCMS.
	 */
    private void processAuth0Callback(HttpServletResponse response, HttpServletRequest request, HttpSession session, String callbackHost, String state, OAuthService service) throws ServletException {
        String stateFromRequest = "";

        if(request.getParameter("state") != null) {
            stateFromRequest = OAuthEncoder.encode(request.getParameter("state"));
        }

        try {
        	// Checking the state parameter is important to prevent CSRF attacks
            if(!stateFromRequest.equals(state)) {
                Logger.info(this.getClass(), "State parameter does not match (" + stateFromRequest + " != " + state + ")!");
                response.reset();
                response.sendError(HttpStatus.SC_UNPROCESSABLE_ENTITY, "state parameter does not match (" + stateFromRequest + " != " + state + ")!");
            } else {
                doCallback(request, response, service);

                String authorizationUrl = (String) session.getAttribute("OAUTH_REDIRECT");
                if (authorizationUrl == null)
                    authorizationUrl = "/?logged-in";
                request.getSession().removeAttribute("OAUTH_REDIRECT");
                response.reset();
                response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                response.setHeader("Location", authorizationUrl);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new ServletException(e);

        }
    }

	/**
	 * Factory method for creating and configuring a Scribe OAuthService.
	 */
    private OAuthService createOAuthService(String CALLBACK_HOST, String state) throws ServletException {
		String apiKey, apiSecret, scopes, oauthHostname;
        String auth0Connection;

		try {
            apiKey = OAuthPropertyBundle.getProperty("Auth02Api_API_KEY");
			apiSecret = OAuthPropertyBundle.getProperty("Auth02Api_API_SECRET");
			scopes = OAuthPropertyBundle.getProperty("Auth02Api_SCOPE");
			oauthHostname = OAuthPropertyBundle.getProperty("Auth02Api_HOSTNAME");
			auth0Connection = OAuthPropertyBundle.getProperty("Auth02Api_CONNECTION");
		} catch (Exception e1) {
			throw new ServletException(e1);
		}

		OAuthService service = new ServiceBuilder()
				.provider(Auth02Api.class)
				.apiKey(apiKey)
				.apiSecret(apiSecret)
				.scope(scopes)
				.callback(CALLBACK_HOST + CALLBACK_URL)
				.build();

		((Auth02Api)service.getApi()).configure(oauthHostname, auth0Connection, state);
		return service;
	}

	private User getUserFromSession(HttpServletRequest request, HttpSession session) {
		User user = null;

		try {
			user = (User) session.getAttribute(com.dotmarketing.util.WebKeys.CMS_USER);
			if (user == null) {
				try {
					user = com.liferay.portal.util.PortalUtil.getUser(request);
				} catch (Exception nsue) {
					Logger.warn(this, "Exception trying to getUser: " + nsue.getMessage(), nsue);
				}
			}
		} catch (Exception nsue) {
			Logger.warn(this, "Exception trying to getUser: " + nsue.getMessage(), nsue);
		}
		return user;
	}

	@Override
	public void init() throws ServletException {
		CALLBACK_URL = OAuthPropertyBundle.getProperty("CALLBACK_URL");
	}

	/**
	 * This method gets the user from the remote service and either creates them
	 * in Dotcms and/or updates an existing user.
	 */
	private void doCallback(HttpServletRequest request, HttpServletResponse response, OAuthService service) throws DotDataException, JSONException {

		JSONObject userResourceJson = getUserResourceFromAuth0(service, request.getParameter("code"));

		User systemUser = APILocator.getUserAPI().getSystemUser();
		User userLoggingIn = null;
		try {
			userLoggingIn = APILocator.getUserAPI().loadByUserByEmail(userResourceJson.getString("email"), systemUser, false);

		} catch (Exception e) {
			Logger.warn(this, "No matching user, creating");
		}
		if (userLoggingIn == null) {
			try {
				userLoggingIn = UserHelper.createUser(userResourceJson);
			} catch (Exception e) {
				Logger.warn(this, "Error creating user:" + e.getMessage(), e);
				throw new DotDataException(e.getMessage());
			}
		}

		if (userLoggingIn.isActive()) {
			List<String> groups = new ArrayList<String>();

			for(int i=0; i < userResourceJson.getJSONArray("groups").size();i++) {
				groups.add(userResourceJson.getJSONArray("groups").getString(i));
			}

			// TODO: Change to AS24-AP-DotCMS-Backend-Users or something similar as soon as groups are mapped correctly
			if(groups.contains("AS24-Azure-ThatsClassified-Team")) {
				UserHelper.updateUserRoles(userLoggingIn, groups);

				LoginFactory.doCookieLogin(PublicEncryptionFactory.encryptString(userLoggingIn.getUserId()), request, response);

				PrincipalThreadLocal.setName(userLoggingIn.getUserId());
				request.getSession().setAttribute(WebKeys.USER_ID, userLoggingIn.getUserId());
			}
		}
	}

	/**
	 * @return The user data from Auth0 including name, email, groups and so on.
	 */
	private JSONObject getUserResourceFromAuth0(OAuthService service, String code) {
		Verifier verifier = new Verifier(code);

		Token accessToken = service.getAccessToken(null, verifier);
		Logger.debug(this.getClass(), "Got the Access Token!");
		OAuthRequest userResourceRequest = new OAuthRequest(Verb.GET, Auth02Api.USER_RESOURCE_URL);
		service.signRequest(accessToken, userResourceRequest);

		String response = userResourceRequest.send().getBody();
		return new JSONTool().generate(response);
	}


	/**
	 * Redirects the user to Auth0 in order to get an access token.
	 */
	private void redirectToAuth0ForAuthentication(HttpServletRequest request, HttpServletResponse response, OAuthService service) {
		String retUrl = (String) request.getAttribute("javax.servlet.forward.request_uri");

		if (request.getSession().getAttribute("OAUTH_REDIRECT") != null) {
			retUrl = (String) request.getSession().getAttribute("OAUTH_REDIRECT");
		}
		if (request.getParameter("referrer") != null) {
			retUrl = request.getParameter("referrer");
		}
		request.getSession().setAttribute("OAUTH_REDIRECT", retUrl);

		String authorizationUrl = service.getAuthorizationUrl(null);
		response.reset();
		response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
		response.setHeader("Location", authorizationUrl);
	}

}
