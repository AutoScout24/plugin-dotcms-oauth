package com.autoscout24.dotcms.authentication.util;

import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.liferay.portal.model.User;

import javax.servlet.ServletException;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class UserHelper {
    private static HashMap<String, String[]> GroupMapping =  new HashMap<String, String[]>() {{
        put("AS24-Azure-ThatsClassified-Team", new String[] {"CMS Administrator"});
    }};

    public static void updateUserRoles(User u, List<String> groups) throws DotDataException {
        Set<Role> newUserRoles = new HashSet<Role>();
        List<Role> currentUserRoles = APILocator.getRoleAPI().loadRolesForUser(u.getUserId());

        for(String group: groups) {
            if(GroupMapping.containsKey(group)) {
                String[] roleKeys = GroupMapping.get(group);
                for(String roleKey: roleKeys) {
                    Role r = APILocator.getRoleAPI().loadRoleByKey(roleKey);
                    newUserRoles.add(r);
                }
            }
        }

        Set<Role> rolesToAdd = new HashSet<Role>();
        rolesToAdd.addAll(newUserRoles);
        rolesToAdd.removeAll(currentUserRoles);

        Set<Role> rolesToRemove = new HashSet<Role>();
        rolesToRemove.addAll(currentUserRoles);
        rolesToRemove.removeAll(newUserRoles);

        for(Role r: rolesToAdd) {
            if (!APILocator.getRoleAPI().doesUserHaveRole(u, r)) {
                APILocator.getRoleAPI().addRoleToUser(r, u);
            }
        }

        for(Role r: rolesToRemove) {
            if (APILocator.getRoleAPI().doesUserHaveRole(u, r)) {
                APILocator.getRoleAPI().removeRoleFromUser(r, u);
            }
        }
    }

    /**
     * Creates a new user in dotCMS using the data retrieved from Auth0.
     *
     * @param json JSON returned by Auth0
     */
    public static User createUser(JSONObject json) throws UnsupportedEncodingException, JSONException, DotDataException, DotSecurityException, ServletException {
        User systemUser = APILocator.getUserAPI().getSystemUser();

        User u;
        String userId = UUIDGenerator.generateUuid();
        String email = new String(json.getString("email").getBytes(), "UTF-8");
        String lastName = new String(json.getString("given_name").getBytes(), "UTF-8");
        String firstName = new String(json.getString("family_name").getBytes(), "UTF-8");

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
}
