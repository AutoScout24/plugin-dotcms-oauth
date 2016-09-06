package com.autoscout24.dotcms.authentication;

import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.business.RoleAPI;
import com.dotmarketing.business.UserAPI;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.CompanyUtils;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.viewtools.MailerTool;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PropsUtil;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * The TimerTask closes vulnerabilities in the authentication process.
 * <p>
 * Goals:
 * - Ensure that a user cannot login anymore after its account was deactivated in Azure AD
 * - Only users having an Azure AD account should be able to login
 * <p>
 * Issues:
 * - We do not get any updates when a user is deactivated in Azure AD or when the groups are changed
 * - Users can change their account manually in the dotCMS backend, especially email address and password
 * - Users can create additional unauthorized accounts only existing in dotCMS
 * - Users can circumvent OAuth authentication by using the native=true query parameter.
 * <p>
 * To mitigate these issues, we want to ensure certain rules:
 * - Users cannot login using the username/password login
 * - All backend users use only email addresses that are part of our Azure AD
 * <p>
 * There is a whitelist for known accounts used by dotCMS for support reasons. These are the only accounts with
 * exceptions to the rules above
 * <p>
 * To ensure the rules are respected, the TimerTask does:
 * - Change all user passwords once a day (thus no user can use username/password login for more than 24h without
 * resetting the password)
 * - Checks that all backend users have an email address controlled by Autoscout24
 */
public class TimerTask extends java.util.TimerTask {

    public static final long PERIOD_IN_MILLISECONDS = 24 * 60 * 60 * 1000;

    @Override
    public void run() {
        try {
            UserAPI userApi = APILocator.getUserAPI();

            List<User> users = userApi.findAllUsers();
            User systemUser = APILocator.getUserAPI().getSystemUser();

            Logger.info(this, "Resetting passwords for all users");
            for (User u : users) {
                if (!shouldValidationBeSkipped(u)) {
                    u.setPassword(PublicEncryptionFactory.digestString(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
                    u.setPasswordEncrypted(true);

                    if (!Arrays.stream(allowedEmailDomains).anyMatch(domain -> u.getEmailAddress().endsWith(domain))) {
                        u.setFirstName("inactive - " + u.getFirstName());
                        u.setActive(false);
                        MailerTool mailerTool = new MailerTool();
                        Logger.warn(this, "Found unauthorized account " + u.getEmailAddress());
                        Logger.info(this, "Sending email from " + CompanyUtils.getDefaultCompany().getEmailAddress());

                        mailerTool.sendEmail("#AS24-ThatsClassified-ds@scout24.com", CompanyUtils.getDefaultCompany().getEmailAddress(),
                                "Unauthorized dotCMS account found",
                                "Found unauthorized account " + u.getEmailAddress() + " on host " + PropsUtil.get(PropsUtil.WEB_SERVER_HOST),
                                false
                        );
                    }

                    APILocator.getUserAPI().save(u, systemUser, false);
                } else {
                    Logger.debug(this, "Skipping user " + u.getEmailAddress());
                }
            }
        } catch (Exception e) {
            Logger.error(this, "Exception during timer task " + e.getClass().getSimpleName() + "(" + e.getStackTrace()[0].getLineNumber() + ")"
                    + ":" + e.getMessage());
        }
    }

    private String[] allowedEmailDomains = {
            "autoscout24.de", "autoscout24.com", "scout24.com", "autoscout24-media.com"
    };

    private String[] emailAddressWhiteList = {
            "admin@dotcms.com", // TODO: Only for the start. Deactivate later. No group accounts.
            "default@dotcms.com", "admin2@dotcms.com", "support@dotcms.com", "anonymous@dotcmsfakeemail.org"
    };

    private boolean shouldValidationBeSkipped(User user) throws DotDataException {
        return Arrays.stream(emailAddressWhiteList).anyMatch(e -> e.equals(user.getEmailAddress())) ||
                !user.isActive() ||
                isFrontendUser(user);
    }

    private boolean isFrontendUser(User user) throws DotDataException {
        RoleAPI roleApi = APILocator.getRoleAPI();

        Stream<Role> roles = roleApi.loadRolesForUser(user.getUserId()).stream()
                .filter(r -> r.getRoleKey() == null || !r.getRoleKey().equals("LoggedIn Site User"))
                .filter(r -> r.getRoleKey() == null || !r.getRoleKey().equals(user.getUserId()));

        return roles.count() == 0;
    }
}
