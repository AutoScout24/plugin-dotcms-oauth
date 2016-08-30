package com.dotcms.osgi.oauth.viewtool;
import java.util.ArrayList;
import java.util.List;

import org.apache.velocity.tools.view.tools.ViewTool;

import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;

public class OAuthTool implements ViewTool {

	private final String NOTSET="xxxxxx";
	@Override
	public void init(Object initData) {
	}

	public List<String> getProviders() {

		java.util.List<String> providers = new ArrayList<String>();


		String auth0 = OAuthPropertyBundle.getProperty("Auth02Api_API_KEY", NOTSET);

		if(!NOTSET.equals(auth0)){
			providers.add(auth0);

		}

		return providers;
		
		
		
		
	}



}
