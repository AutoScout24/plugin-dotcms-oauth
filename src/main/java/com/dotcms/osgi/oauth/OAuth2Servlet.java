/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have
 * chosen to have their login information remembered.
 * Creates a valid WebSession object and
 * passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Date;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.autoscout24.dotcms.authentication.api.Auth02Api;
import com.dotcms.repackage.javax.xml.bind.DatatypeConverter;
import com.dotcms.repackage.org.apache.commons.httpclient.HttpStatus;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.json.JSONException;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.cms.login.factories.LoginFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
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

    private void processAuth0Callback(HttpServletResponse response, HttpServletRequest request, HttpSession session, String callbackHost, String state, OAuthService service) throws ServletException {
        String stateFromRequest = "";

        if(request.getParameter("state") != null) {
            stateFromRequest = OAuthEncoder.encode(request.getParameter("state"));
        }

        try {
            if(!stateFromRequest.equals(state)) {
                Logger.info(this.getClass(), "State parameter does not match (" + stateFromRequest + " != " + state + ")!");
                response.reset();
                response.sendError(HttpStatus.SC_UNPROCESSABLE_ENTITY, "state parameter does not match (" + stateFromRequest + " != " + state + ")!");
            } else {
                doCallback(request, response, service, callbackHost);

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
	 * in Dotcms and/or updates
	 * 
	 * @param request
	 * @param service
	 * @throws DotDataException
	 */
	private void doCallback(HttpServletRequest request, HttpServletResponse response, OAuthService service, String callBackUrl) throws DotDataException {

		JSONObject userResourceJson = getUserResourceFromAuth0(service, callBackUrl, request.getParameter("code"));

		User systemUser = APILocator.getUserAPI().getSystemUser();
		User userLoggingIn = null;
		try {
			userLoggingIn = APILocator.getUserAPI().loadByUserByEmail(userResourceJson.getString("email"), systemUser, false);

		} catch (Exception e) {
			Logger.warn(this, "No matching user, creating");
		}
		if (userLoggingIn == null) {
			try {
				userLoggingIn = createUser(userResourceJson, systemUser);
			} catch (Exception e) {
				Logger.warn(this, "Error creating user:" + e.getMessage(), e);
				throw new DotDataException(e.getMessage());
			}
		}

		if (userLoggingIn.isActive()) {
			updateUserRoles(userLoggingIn);

			LoginFactory.doCookieLogin(PublicEncryptionFactory.encryptString(userLoggingIn.getUserId()), request, response);

    		PrincipalThreadLocal.setName(userLoggingIn.getUserId());
			request.getSession().setAttribute(WebKeys.USER_ID, userLoggingIn.getUserId());
		}
	}

	private JSONObject getUserResourceFromAuth0(OAuthService service, String callBackUrl, String code) {
		Verifier verifier = new Verifier(code);

		Token accessToken = service.getAccessToken(null, verifier);
		Logger.debug(this.getClass(), "Got the Access Token!");

		OAuthRequest userResourceRequest = new OAuthRequest(Verb.GET, callBackUrl);
		service.signRequest(accessToken, userResourceRequest);

		return new JSONTool().generate(userResourceRequest.send().getBody());
	}

	// TODO: Extract roles from groups
	private void updateUserRoles(User u) throws DotDataException {
		StringTokenizer st = new StringTokenizer("", ",;");
		while (st.hasMoreElements()) {
			String roleKey = st.nextToken().trim();
			Role r = APILocator.getRoleAPI().loadRoleByKey(roleKey);
			if(r==null){
				continue;

			}
			if (!APILocator.getRoleAPI().doesUserHaveRole(u, r)) {
				APILocator.getRoleAPI().addRoleToUser(r, u);
			}
		}
	}

	private User createUser(JSONObject json, User systemUser) throws UnsupportedEncodingException, JSONException, DotDataException, DotSecurityException, ServletException {
		String FIRST_NAME_PROP, LAST_NAME_PROP;

		try {
			FIRST_NAME_PROP = OAuthPropertyBundle.getProperty("Auth02Api_FIRST_NAME_PROP");
			LAST_NAME_PROP = OAuthPropertyBundle.getProperty("Auth02Api_LAST_NAME_PROP");
		} catch (Exception e1) {
			throw new ServletException(e1);
		}

		User u;
		String userId = UUIDGenerator.generateUuid();
		String email = new String(json.getString("email").getBytes(), "UTF-8");
		String lastName = new String(json.getString(FIRST_NAME_PROP).getBytes(), "UTF-8");
		String firstName = new String(json.getString(LAST_NAME_PROP).getBytes(), "UTF-8");

		u = APILocator.getUserAPI().createUser(userId, email);

		u.setFirstName(firstName);
		u.setLastName(lastName);
		u.setActive(true);

		u.setCreateDate(new Date());
		u.setPassword(PublicEncryptionFactory.digestString(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
		u.setPasswordEncrypted(true);

		APILocator.getUserAPI().save(u, systemUser, false);
		return u;
	}

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
