plugins-dotcms-oauth
====================

This is an osgi plugin initially copied from DotCMS. It uses Auth0 for authentication. It can be tested by 
running Auth02Example.

We use Auth0 for backend login and native username/password login for frontend.

When a new user logs in with SSO, the user is created in the local database with a random password. We synchronize 
Azure AD groups with dotCMS roles on each login.

We disabled the native parameter to use the original authentication method. This would defeat the purpose of
our SSO implementation. When a user changes his own password, he could still use the native form to login although
he was deleted from Azure AD. By disabling the form, logging in is only possible with SSO.

## Building
To download and build,clone the repo, cd into the cloned directoy and run
```
git clone git@github.com:AutoScout24/plugin-dotcms-oauth.git
cd ./plugin-dotcms-oauth
./gradlew -Pauth0ApiKey=XXX -Pauth0ApiSecret=XXX release
```
the plugin will be built under ./build/lib/plugin-dotcms-oauth-release-0.1.jar

The API_KEY and API_SECRET can be found in LastPass. 

**WARNING:** Deploying an OSGi bundle without proper configuration can leave you locked out of dotCMS. 

## Deployment
**WARNING:** The deployment process is ugly and risky, especially since we have no access to the machines. Since we don't think this
plugin should change very often and it's difficult to make it better, we leave it like this for now. But make sure to read the whole
documentation and understand the consequences before attempting a deployment.

After the bundle was build, upload it to the server manually in the administration backend. Please check that authentication is still working
in a second browser before logging out. This is to ensure that authentication is still working. 

If authentication is broken, you can't login to upload a fixed OSGi bundle. You will need a support ticket to gain access to dotCMS again.

## Using

This plugin "rewrites" the urls Dotcms uses to login (both front and backend) and points them to the OAuth provider specified.  You can see and or add/delete/modify these "rewrites" in the Activator class here.  

https://github.com/dotCMS/plugin-dotcms-oauth/blob/master/src/main/java/com/dotcms/osgi/oauth/Activator.java

If you want to avoid using oauth and authenticate via the standard Dotcms authentication, you can pass the url parameter native=true like this:

Backend native login:
````
http://localhost:8080/html/portal/login.jsp?native=true 
````

## Known issues
DotCMS do have their own user accounts needed for system administration and support:
* Admin2 User (admin2@dotcms.com)
* dotCMS Support (support@dotcms.com)

Futhermore there are Accounts used by the system
* default@dotcms.com
* anonymous user anonymous (anonymous@dotcmsfakeemail.org)

They have to login using the native login. Our user synchronization tool must allow these users to exist although
they do not exist in Azure AD.

Risks associated with native login:
* Scout24 users could use native login instead of SSO. Since groups/roles are only synchronized on login with Auth0,
  a user can maintain permissions that are already removed from Azure AD
* Any admin could change the password of one of the dotcms accounts and use them when their Azure AD account is cancelled.  

Possible measures:
* We can update roles regularly from an external script that is also removing old accounts
* Most actions are logged by DotCMS. While we cannot prevent the second issue from happening easily, it will leave traces
  and it should be possible to find out who did it in retrospective. 
* Limit Admin access in general to a low number of people
* Do not use team account, but individual accounts for every admin.

## OSGi Exports
Below is a list of exports that are required by this plugin
```
org.apache.velocity.tools.view.tools,
org.apache.velocity.tools.view.servlet,
org.apache.velocity.tools.view,
javax.xml.bind,
com.liferay.portal.util,
com.liferay.portal.model,
com.liferay.portal.auth,
com.dotmarketing.viewtools,
com.dotmarketing.util.json,
com.dotmarketing.util,
com.dotmarketing.osgi,
com.dotmarketing.filters,
com.dotmarketing.exception,
com.dotmarketing.cms.login.factories,
com.dotmarketing.cms.factories,
com.dotmarketing.business,
```

## Troubleshooting
If you get an exception with the TLS algorithm, e.g. something like:

`javax.net.ssl.SSLHandshakeException: Could not generate secret`

You can disable DHE as a supported algorithm in your `JAVA_HOME/lib/security/java.security` file, e.g.
```
jdk.tls.disabledAlgorithms=SSLv3, DHE.
```
