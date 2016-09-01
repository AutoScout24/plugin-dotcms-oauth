package com.dotcms.osgi.oauth;


import java.util.ArrayList;
import java.util.List;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;
import com.dotcms.osgi.oauth.viewtool.OAuthToolInfo;
import com.dotcms.repackage.org.apache.felix.http.api.ExtHttpService;
import com.dotcms.repackage.org.apache.logging.log4j.core.LoggerContext;
import com.dotcms.repackage.org.osgi.framework.BundleContext;
import com.dotcms.repackage.org.osgi.framework.ServiceReference;
import com.dotcms.repackage.org.osgi.util.tracker.ServiceTracker;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.Condition;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.NormalRule;
import com.dotcms.repackage.org.tuckey.web.filters.urlrewrite.Rule;
import com.dotmarketing.filters.DotUrlRewriteFilter;
import com.dotmarketing.loggers.Log4jUtil;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotcms.repackage.org.apache.logging.log4j.LogManager;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {

	private List<Rule> rules = new ArrayList<Rule>();
	private ExtHttpService httpService;
	private ServiceTracker<ExtHttpService, ExtHttpService> serviceTracker;
	private OAuth2Servlet servlet;
	private final String OAUTH_URL = "/oauth2";
    private LoggerContext pluginLoggerContext;

	@SuppressWarnings("unchecked")
	public void start(BundleContext context) throws Exception {
        //Initializing log4j...
        LoggerContext dotcmsLoggerContext = Log4jUtil.getLoggerContext();
        //Initialing the log4j context of this plugin based on the dotCMS logger context
        pluginLoggerContext = (LoggerContext) LogManager.getContext(this.getClass().getClassLoader(),
                false,
                dotcmsLoggerContext,
                dotcmsLoggerContext.getConfigLocation()
        );

		Logger.info(this, "Starting OSGi OAuth Filter");
		serviceTracker = new ServiceTracker<ExtHttpService, ExtHttpService>(context, OAuth2Servlet.class.getName(), null);

		// Initializing services...
		initializeServices(context);

		
		
		String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR","").toLowerCase();
		boolean frontEnd = useFor.contains ("frontend");
		boolean backEnd = useFor.contains ("backend");

		registerViewToolService(context, new OAuthToolInfo());
		
		
		
		ServiceReference<ExtHttpService> sRef = (ServiceReference<ExtHttpService>) context.getServiceReference(ExtHttpService.class.getName());
        if ( sRef != null ) {

        	serviceTracker.addingService( sRef );
            httpService = (ExtHttpService) context.getService( sRef );
            try {
                //Registering a simple test servlet
            	servlet = new OAuth2Servlet();
                httpService.registerServlet( OAUTH_URL, servlet, null, null );

            } catch ( Exception e ) {
                e.printStackTrace();
            }
        }

		// open service tracker to start tracking
		serviceTracker.open();

		NormalRule rule = new NormalRule();
		
		
        //Create Conditions for this rule
        Condition condition1 = new Condition();

		condition1 = new Condition();
        condition1.setName( "native" );
        condition1.setType("parameter");
        condition1.setOperator("notequal");
        condition1.setValue( "^.+$" );
        
        //Create another Condition for this rule
        Condition condition2 = new Condition();
        condition2.setName( "my_account_r_m" );
        condition2.setType("parameter");
        condition2.setOperator("notequal");
        condition2.setValue( "^.+$" );

        rules = new ArrayList<Rule>();
        if(frontEnd){
	        rule = new NormalRule();
			rule.setName("oauth-rule" + rules.size());
			rule.setFrom("^/dotCMS/login.*$");
			rule.setTo("/app" + OAUTH_URL);
			rule.addCondition(condition1);
			rule.addCondition(condition2);
			addRewriteRule(rule);
			rules.add(rule);
        }
		
		
        if(backEnd){
			rule = new NormalRule();
			rule.setName("oauth-rule" + rules.size());
			rule.setFrom("^/html/portal/login.*$");
			rule.setTo("/app" + OAUTH_URL + "?referrer=/c/portal/layout");
			rule.addCondition(condition1);
			rule.addCondition(condition2);
			addRewriteRule(rule);
			rules.add(rule);
			
			
			rule = new NormalRule();
			rule.setName("oauth-rule" + rules.size());
			rule.setFrom("^/c/public/login.*$");
			rule.setTo("/app" + OAUTH_URL + "?referrer=/c/portal/layout");
			rule.addCondition(condition1);
			rule.addCondition(condition2);
			addRewriteRule(rule);
			rules.add(rule);
			
			
			rule = new NormalRule();
			rule.setName("oauth-rule" + rules.size());
			rule.setFrom("^/c/portal_public/login.*$");
			rule.setTo("/app" + OAUTH_URL + "?referrer=/c/portal/layout");
			rule.addCondition(condition1);
			rule.addCondition(condition2);
			addRewriteRule(rule);
			rules.add(rule);
			
			
			
			
			rule = new NormalRule();
			rule.setName("oauth-rule" + rules.size());
			rule.setFrom("^/c/portal/logout.*$");
			rule.setTo("/c/portal/logout?referer=/");
			rule.addCondition(condition1);
			rule.addCondition(condition2);
			addRewriteRule(rule);
			rules.add(rule);
        }
		
		Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");

	}

	public void stop(BundleContext context) throws Exception {
        //Unregister the servlet
        if ( httpService != null && servlet != null ) {
            httpService.unregisterServlet( servlet );
        }

		Logger.info(this.getClass(), "Removing OSGi OAuth Servlet");

        for(Rule rule : rules) {
			DotUrlRewriteFilter.getUrlRewriteFilter().removeRule(rule);
		}

		Logger.info(this.getClass(), "We now have " + DotUrlRewriteFilter.getUrlRewriteFilter().getRules().size() + " rules");
		// close service tracker to stop tracking
		serviceTracker.close();

        unregisterServices(context);

        //Shutting down log4j in order to avoid memory leaks
        Log4jUtil.shutdown(pluginLoggerContext);
    }

}