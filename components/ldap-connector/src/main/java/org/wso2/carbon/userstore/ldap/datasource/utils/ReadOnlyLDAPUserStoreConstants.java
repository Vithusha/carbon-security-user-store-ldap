/*
 * Copyright 2005-2007 WSO2, Inc. (http://wso2.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.userstore.ldap.datasource.utils;


import org.wso2.carbon.userstore.ldap.resources.Property;

import java.util.ArrayList;

public class ReadOnlyLDAPUserStoreConstants {


    //Properties for Read Write LDAP User Store Manager
    public static final ArrayList<Property> ROLDAP_USERSTORE_PROPERTIES = new ArrayList<Property>();
    public static final ArrayList<Property> OPTIONAL_ROLDAP_USERSTORE_PROPERTIES = new ArrayList<Property>();

    //For multiple attribute separation
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private static final String MULTI_ATTRIBUTE_SEPARATOR_DESCRIPTION = "This is the separator for multiple claim values";
    private static final String DisplayNameAttributeDescription = "Attribute name to display as the Display Name";
    private static final String DisplayNameAttribute = "DisplayNameAttribute";
    private static final String roleDNPattern = "RoleDNPattern";
    private static final String roleDNPatternDescription = "The patten for role's DN. It can be defined to improve " +
            "the LDAP search";


    static {

        setMandatoryProperty(IdentityStoreConfigConstants.connectionURL, "Connection URL", "ldap://",
                IdentityStoreConfigConstants.connectionURLDescription, false);
        setMandatoryProperty(IdentityStoreConfigConstants.connectionName, "Connection Name", "uid=," +
                "ou=", IdentityStoreConfigConstants.connectionNameDescription, false);
        setMandatoryProperty(IdentityStoreConfigConstants.connectionPassword, "Connection Password",
                "", IdentityStoreConfigConstants.connectionPasswordDescription, true);
        setMandatoryProperty(IdentityStoreConfigConstants.userSearchBase, "User Search Base",
                "ou=system", IdentityStoreConfigConstants.userSearchBaseDescription, false);
        setMandatoryProperty(IdentityStoreConfigConstants.userNameAttribute, "Username Attribute",
                "", IdentityStoreConfigConstants.userNameAttributeDescription, false);

        setMandatoryProperty(IdentityStoreConfigConstants.usernameSearchFilter, "User Search Filter",
                "(&amp;(objectClass=person)(uid=?))", IdentityStoreConfigConstants
                        .usernameSearchFilterDescription, false);
        setMandatoryProperty(IdentityStoreConfigConstants.usernameListFilter, "User List Filter",
                "(objectClass=person)", IdentityStoreConfigConstants.usernameListFilterDescription, false);


        setProperty(IdentityStoreConfigConstants.userDNPattern, "User DN Pattern", "", IdentityStoreConfigConstants.userDNPatternDescription);
        setProperty(DisplayNameAttribute, "Display name attribute", "uid", DisplayNameAttributeDescription);
        setProperty(IdentityStoreConfigConstants.disabled, "Disabled", "false", IdentityStoreConfigConstants.disabledDescription);
        setProperty(IdentityStoreConfigConstants.readGroups, "Read Groups", "true", IdentityStoreConfigConstants
                .readLDAPGroupsDescription);
        setProperty(IdentityStoreConfigConstants.groupSearchBase, "Group Search Base", "ou=Groups,dc=wso2,dc=com",
                IdentityStoreConfigConstants.groupSearchBaseDescription);
        setProperty(IdentityStoreConfigConstants.groupNameAttribute, "Group Name Attribute", "cn", IdentityStoreConfigConstants.groupNameAttributeDescription);
        setProperty(IdentityStoreConfigConstants.groupNameSearchFilter, "Group Search Filter",
                "(&amp;(objectClass=groupOfNames)(cn=?))", IdentityStoreConfigConstants.groupNameSearchFilterDescription);
        setProperty(IdentityStoreConfigConstants.groupNameListFilter, "Group List Filter", "(objectClass=groupOfNames)",
                IdentityStoreConfigConstants.groupNameListFilterDescription);

        setProperty(roleDNPattern, "Role DN Pattern", "", roleDNPatternDescription);

        setProperty(IdentityStoreConfigConstants.membershipAttribute, "Membership Attribute", "member", IdentityStoreConfigConstants.membershipAttributeDescription);
        setProperty(IdentityStoreConfigConstants.memberOfAttribute, "Member Of Attribute", "", IdentityStoreConfigConstants.memberOfAttribute);
        setProperty("BackLinksEnabled", "Enable Back Links", "false", " Whether to allow attributes to be result from" +
                "references to the object from other objects");

        setProperty("ReplaceEscapeCharactersAtUserLogin", "Enable Escape Characters at User Login", "true", "Whether replace escape character when user login");
        setProperty("UniqueID", "", "", "");

    }



    private static void setMandatoryProperty(String name, String displayName, String value,
                                             String description, boolean encrypt) {
        String propertyDescription = displayName + "#" + description;
        if (encrypt) {
            propertyDescription += "#encrypt";
        }
        Property property = new Property(name, value, propertyDescription, null);
        ROLDAP_USERSTORE_PROPERTIES.add(property);

    }

    private static void setProperty(String name, String displayName, String value,
                                    String description) {
        Property property = new Property(name, value, displayName + "#" + description, null);
        OPTIONAL_ROLDAP_USERSTORE_PROPERTIES.add(property);

    }


}
