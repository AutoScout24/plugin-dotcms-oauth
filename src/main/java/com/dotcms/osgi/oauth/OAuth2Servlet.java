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
import java.util.Date;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
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

public class OAuth2Servlet extends HttpServlet {

	private static final long serialVersionUID = -7036009330382977246L;
	
	public void destroy() {

	}

	public OAuth2Servlet() {
		
	}

	private static String CALLBACK_URL, ROLES_TO_ADD;
	String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR","").toLowerCase();
	boolean frontEnd = useFor.contains ("frontend");
	boolean backEnd = useFor.contains ("backend");
	
	@Override
	public void service(ServletRequest req, ServletResponse res) throws IOException, ServletException {

		HttpServletResponse response = (HttpServletResponse) res;
		HttpServletRequest request = (HttpServletRequest) req;
		HttpSession session = request.getSession(false);
		String path = request.getRequestURI();
		User user = null;

		String CALLBACK_HOST, API_KEY, API_SECRET, OAUTH_PROVIDER, PROTECTED_RESOURCE_URL, SCOPE, FIRST_NAME_PROP, LAST_NAME_PROP, OAUTH_HOSTNAME;
		
		CALLBACK_HOST = request.getScheme() + "://" + ((request.getServerPort() == 80 || request.getServerPort() == 443) ? 
						request.getServerName() : request.getServerName()+":"+request.getServerPort());

		OAUTH_PROVIDER = OAuthPropertyBundle.getProperty("DEFAULT_OAUTH_PROVIDER");
		if (session.getAttribute("OAUTH_PROVIDER") != null) {
			OAUTH_PROVIDER = (String) session.getAttribute("OAUTH_PROVIDER");
		}
		if (request.getParameter("OAUTH_PROVIDER") != null) {
			OAUTH_PROVIDER = request.getParameter("OAUTH_PROVIDER");
		}
		session.setAttribute("OAUTH_PROVIDER", OAUTH_PROVIDER);

		String proName;
		Api provider;
		try {
			proName = "Auth02Api";

			API_KEY = OAuthPropertyBundle.getProperty(proName + "_" + "API_KEY");
			API_SECRET = OAuthPropertyBundle.getProperty(proName + "_" + "API_SECRET");
			PROTECTED_RESOURCE_URL = OAuthPropertyBundle.getProperty(proName + "_" + "PROTECTED_RESOURCE_URL");
			SCOPE = OAuthPropertyBundle.getProperty(proName + "_" + "SCOPE");
			FIRST_NAME_PROP = OAuthPropertyBundle.getProperty(proName + "_" + "FIRST_NAME_PROP");
			LAST_NAME_PROP = OAuthPropertyBundle.getProperty(proName + "_" + "LAST_NAME_PROP");
			OAUTH_HOSTNAME = OAuthPropertyBundle.getProperty(proName + "_" + "HOSTNAME");

			provider = new com.autoscout24.dotcms.authentication.api.Auth02Api(OAUTH_HOSTNAME);
		} catch (Exception e1) {
			throw new ServletException(e1);
		}

		// get our user
		try {
			user = (com.liferay.portal.model.User) session.getAttribute(com.dotmarketing.util.WebKeys.CMS_USER);
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

		// if the user is already logged in
		if (user != null) {
			Logger.error(this.getClass(), "Already logged in, redirecting home");
			response.reset();
			response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			response.setHeader("Location", "/?already-logged-in");
			return;
		}

		// set up Oauth service
		OAuthService service = new ServiceBuilder()
				.provider(provider.getClass())
				.apiKey(API_KEY)
				.apiSecret(API_SECRET)
				.scope(SCOPE)
				.callback(CALLBACK_HOST + CALLBACK_URL)
				.build();
		if (path.contains(CALLBACK_URL)) {
			try {

				doCallback(request, response, service, PROTECTED_RESOURCE_URL, FIRST_NAME_PROP, LAST_NAME_PROP);
				
				// redirect onward!
				String authorizationUrl = (String) session.getAttribute("OAUTH_REDIRECT");
				if (authorizationUrl == null)
					authorizationUrl = "/?logged-in";
				request.getSession().removeAttribute("OAUTH_REDIRECT");
				response.reset();
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", authorizationUrl);
			} catch (Exception e) {
				e.printStackTrace();
				throw new ServletException(e);

			}

		} else {
			// Send for authorization
			sendForAuthorization(request, response, service);
		}

	}

	@Override
	public void init() throws ServletException {

		ROLES_TO_ADD = OAuthPropertyBundle.getProperty("ROLES_TO_ADD");
		CALLBACK_URL = OAuthPropertyBundle.getProperty("CALLBACK_URL");

	}

	/**
	 * This method gets the user from the remote service and either creates them
	 * in Dotcms and/or updates
	 * 
	 * @param request
	 * @param service
	 * @return
	 * @throws DotDataException
	 */
	private User doCallback(HttpServletRequest request, HttpServletResponse response, OAuthService service, String callBackUrl,
			String firstNameProp, String lastNameProp) throws DotDataException {

		Verifier verifier = new Verifier(request.getParameter("code"));

		Token accessToken = service.getAccessToken(null, verifier);
		Logger.debug(this.getClass(), "Got the Access Token!");

		OAuthRequest quest = new OAuthRequest(Verb.GET, callBackUrl);
		service.signRequest(accessToken, quest);
		Response sponse = quest.send();

		JSONObject json = new JSONTool().generate(sponse.getBody());

		User sys = APILocator.getUserAPI().getSystemUser();
		User u = null;
		try {
			u = APILocator.getUserAPI().loadByUserByEmail(json.getString("email"), sys, false);

		} catch (Exception e) {
			Logger.warn(this, "No matching user, creating");
		}
		if (u == null) {
			try {

				String userId = UUIDGenerator.generateUuid();
				String email = new String(json.getString("email").getBytes(), "UTF-8");
				String lastName = new String(json.getString(lastNameProp).getBytes(), "UTF-8");
				String firstName = new String(json.getString(firstNameProp).getBytes(), "UTF-8");

				u = APILocator.getUserAPI().createUser(userId, email);

				u.setFirstName(firstName);
				u.setLastName(lastName);
				u.setActive(true);

				u.setCreateDate(new Date());
				u.setFemale("female".equals(json.getString("gender")));
				u.setPassword(PublicEncryptionFactory.digestString(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
				u.setPasswordEncrypted(true);

				APILocator.getUserAPI().save(u, sys, false);

			} catch (Exception e) {
				Logger.warn(this, "Error creating user:" + e.getMessage(), e);
				throw new DotDataException(e.getMessage());
			}
		}

		if (!u.isActive()) {
			return u;
		}

		StringTokenizer st = new StringTokenizer(ROLES_TO_ADD, ",;");
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
		LoginFactory.doCookieLogin(PublicEncryptionFactory.encryptString(u.getUserId()), request, response);
		if(backEnd){
			PrincipalThreadLocal.setName(u.getUserId());
			request.getSession().setAttribute(WebKeys.USER_ID, u.getUserId());
		}

		return u;

	}

	private void sendForAuthorization(HttpServletRequest request, HttpServletResponse response, OAuthService service) {
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
		return;
	}

}
