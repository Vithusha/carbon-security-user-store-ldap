/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.userstore.ldap.connector;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.bean.Group;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.*;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnector;
import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConstants;
import org.wso2.carbon.userstore.ldap.datasource.utils.DatabaseColumnNames;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConnectionContext;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.*;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;



/**
 * LDAP based implementation for identity store connector.
 */
public class LDAPIdentityStoreConnector implements IdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(LDAPIdentityStoreConnector.class);

    protected DataSource dataSource;
    protected IdentityStoreConnectorConfig identityStoreConfig;
    protected String identityStoreId;
    protected String connectorUserId;
    protected String connectorGroupId;
    protected LDAPConnectionContext connectionSource = null;
    protected Map<String, String> properties;


    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig) throws IdentityStoreConnectorException {

        this.properties = identityStoreConnectorConfig.getProperties();
        this.identityStoreId = identityStoreConnectorConfig.getConnectorId();
        this.identityStoreConfig = identityStoreConnectorConfig;


        try {
            connectionSource = new LDAPConnectionContext(properties);

        } catch (DataSourceException e) {
            throw new IdentityStoreConnectorException("Error occurred while initiating data source.", e);
        }


        if (log.isDebugEnabled()) {
            log.debug("LDAP identity store with id: {} initialized successfully.", identityStoreId);
            System.out.println("Init method is invoked properly");
        }

        //TODO check whether this is okay to be a property
        connectorUserId = identityStoreConfig.getProperties().get("connectorUserId");
        connectorGroupId = identityStoreConfig.getProperties().get("connectorGroupId");
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }

    @Override
    public String getConnectorUserId(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreConnectorException {
        return connectorUserId;
    }

    @Override
    public List<String> listConnectorUserIds(String s, String s1, int i, int i1) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorUserIdsByPattern(String s, String s1, int i, int i1) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public int getUserCount() throws IdentityStoreConnectorException {


        int count = 0;
        String searchFilter = "(objectClass=user)";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        try {
           DirContext context=  connectionSource.getContext();

            //TODO : Check the searchbase functionality
            NamingEnumeration answer = context.search("", searchFilter, searchControls);
            while (answer.hasMore()) {

                ++count;
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occurred while getting user count.", e);
        }
        return count;
    }


    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }


        List<User.UserBuilder> userList = new ArrayList<>();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setCountLimit(length);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.User.USER_UNIQUE_ID});

        try {
            DirContext context = connectionSource.getContext();
            NamingEnumeration answer = context.search(attributeName, getFinalFilters(filterPattern), searchControls);
            while (answer.hasMore()) {
                String userUniqueId = answer.toString();
                userList.add(new User.UserBuilder().setUserId(userUniqueId));
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        }


        return userList;
    }


    public List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern) throws
            IdentityStoreException {
        return getUserBuilderList(attributeName, filterPattern, 0, -1);
    }


    @Override
    public List<Attribute> getUserAttributeValues(String userName) throws IdentityStoreConnectorException {
        DirContext context;
        List<String> attr_list = new ArrayList<>();
        try {
            context = connectionSource.getContext();
            Attributes attrs = context.getAttributes("cn="+ userName);
            for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
                attr_list.add(ae.next().toString());
            }


            return getUserAttributeValues(userName, attr_list);

        } catch (NamingException|IdentityStoreConnectorException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occured while getting the user Attributes ", e);
        }


    }

    @Override
    public List<Attribute> getUserAttributeValues(String userName, List<String> attributeNames) throws IdentityStoreConnectorException {
        Map<String, Integer> repetitions = new HashMap<>();

        List<Attribute> userAttributes = new ArrayList<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());

        Map<String, Integer> repetition = new HashMap<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());
        String[] attributeArray = new String[attributeNames.size()];
        attributeArray = attributeNames.toArray(attributeArray);
        String filter = "(&(objectClass=inetOrgPerson)(dc=wso2,dc=com))";
        try {
            DirContext context = connectionSource.getContext();

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(attributeArray);

            //NamingEnumeration<> resultSet=context.search(" ",filter,searchControls);
            NamingEnumeration<SearchResult> answer = context.search("cn="+userName, filter, searchControls);


            if (answer.hasMore()) {
                Attributes attrs = answer.next().getAttributes();

                for (String s : attributeArray) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(s);
                    attribute.setAttributeValue(String.valueOf(attrs.get(s)));
                    userAttributes.add(attribute);
                }


            }

            if (log.isDebugEnabled()) {
                log.debug("{} attributes of user: {} retrieved from identity store: {}.", userAttributes.size(),
                        userName, identityStoreId);
            }

            return userAttributes;


        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occured while retreiving Group Attribute values" + e);
        }
    }


    public Group.GroupBuilder getGroupBuilder(String attributeName, String filterPattern) throws GroupNotFoundException,
            IdentityStoreException {
        Group.GroupBuilder group = new Group.GroupBuilder();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.Group.GROUP_UNIQUE_ID});

        try {
            DirContext context = connectionSource.getContext();
            NamingEnumeration answer = context.search(attributeName, getFinalFilters(filterPattern), searchControls);
            while (answer.hasMore()) {
                String groupUniqueId = answer.toString();
                group.setGroupId(groupUniqueId);
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        }

        return group;
    }

    @Override
    public int getGroupCount() throws IdentityStoreConnectorException {
        int count = 0;
        String searchFilter = "(objectClass=group)";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        try {
            DirContext context = connectionSource.getContext();

            //TODO : Check the searchbase functionality
            NamingEnumeration answer = context.search(LDAPConstants.USER_SEARCH_BASE, searchFilter, searchControls);
            while (answer.hasMore()) {

                ++count;
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occurred while getting user count.", e);
        }
        return count;
    }

    @Override
    public String getConnectorGroupId(String s, String s1) throws GroupNotFoundException, IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorGroupIds(String s, String s1, int i, int i1) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public List<String> listConnectorGroupIdsByPattern(String s, String s1, int i, int i1) throws IdentityStoreConnectorException {
        return null;
    }


    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length) throws
            IdentityStoreException {
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }


        List<Group.GroupBuilder> groupList = new ArrayList<>();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setCountLimit(length);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.Group.GROUP_UNIQUE_ID});

        try {
            DirContext context = connectionSource.getContext();
            NamingEnumeration answer = context.search(DatabaseColumnNames.Group.GROUP_NAME,
                    getFinalFilters(filterPattern), searchControls);

            while (answer.hasMore()) {
                String groupUniqueId = answer.toString();
                groupList.add(new Group.GroupBuilder().setGroupId(groupUniqueId));
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreException("An error occurred while getting the group ", e);
        }


        return groupList;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupName) throws IdentityStoreConnectorException {
        DirContext context;
        List<String> attr_list = new ArrayList<>();
        try {
            context = connectionSource.getContext();
            Attributes attrs = context.getAttributes("(&(objectClass=user)(ou=" + groupName);
            for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
                attr_list.add((String) ae.next());
            }


            return getUserAttributeValues(groupName, attr_list);

         } catch (NamingException|IdentityStoreConnectorException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occured while getting the group Attributes ", e);
        }
    }


    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames) throws
            IdentityStoreConnectorException {


        Map<String, Integer> repetitions = new HashMap<>();

        List<Attribute> userAttributes = new ArrayList<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());

        Map<String, Integer> repetition = new HashMap<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());
        String[] attributeArray = new String[attributeNames.size()];
        attributeArray = attributeNames.toArray(attributeArray);
        String filter = "(&(objectClass=group)(ou =" + groupId + ")";
        try {
            DirContext context = connectionSource.getContext();

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(attributeArray);

            //NamingEnumeration<> resultSet=context.search(" ",filter,searchControls);
            NamingEnumeration<SearchResult> answer = context.search(" ", filter, searchControls);


            if (answer.hasMore()) {
                Attributes attrs = answer.next().getAttributes();

                for (String s : attributeArray) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(s);
                    attribute.setAttributeValue(String.valueOf(attrs.get(s)));
                    userAttributes.add(attribute);
                }

                ;
            }

            if (log.isDebugEnabled()) {
                log.debug("{} attributes of user: {} retrieved from identity store: {}.", userAttributes.size(),
                        groupId, identityStoreId);
            }

            return userAttributes;


        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occured while retreiving Group Attribute values" + e);
        }

    }


    public List<Group.GroupBuilder> getGroupBuildersOfUser(String userName) throws IdentityStoreException {
        List<Group.GroupBuilder> groupList = new ArrayList<>();
        try {
            DirContext context = connectionSource.getContext();

            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String searchFilter = "(&(objectClass=user)(CN=" + userName + "))";
            String searchBase = " ";

            //Specify the attributes to return
            String returnedAtts[] = {"memberOf"};
            searchCtls.setReturningAttributes(returnedAtts);

            NamingEnumeration answer = context.search(searchBase, searchFilter, searchCtls);

            //Loop through the search results
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();


                //Print out the groups

                Attributes attrs = sr.getAttributes();
                if (attrs != null) {


                    for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
                        Attributes attr = (Attributes) ae.next();
                        for (NamingEnumeration groupIds = attr.getIDs(); groupIds.hasMore(); ) {
                            String groupId = (String) groupIds.next();
                            Group.GroupBuilder group = new Group.GroupBuilder().setGroupId(groupId);
                            groupList.add(group);
                        }
                    }
                }
            }

            context.close();

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreException("Error occured while listing groups of the user: " + e);
        }
        return groupList;
    }


    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreConnectorException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.User.USER_UNIQUE_ID});
        boolean isUser = false;

        try {
            DirContext context = connectionSource.getContext();
            String filterPattern = "(&(objectClass=user)(" + DatabaseColumnNames.User.USER_UNIQUE_ID + "="
                    + userId + ") " + "(memberof = CN = " + groupId + ",OU=Users))";
            NamingEnumeration answer = context.search(userId, filterPattern, searchControls);
            while (answer.hasMore()) {
                isUser = true;
            }
        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException();
        }

        return isUser;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreConnectorException {
        return true;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    @Override
    public String addUser(List<Attribute> attributes) throws IdentityStoreConnectorException {


        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);




        if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {

            throw new IdentityStoreConnectorException("Primary Attribute " + connectorUserId + " is not found among the " +
                        "attribute list");
            }
        BasicAttribute attr;
        BasicAttributes entry = new BasicAttributes();
        int i=0;
        for (Attribute attribute : attributes) {

            String name = attribute.getAttributeName();
            String value = attribute.getAttributeValue();
            attr = new BasicAttribute(name, value);
            entry.put(attr);

        }

        BasicAttribute objClass = new BasicAttribute("objectClass");

        //TODO: Check the objectClass is correct with user
        objClass.add("top");
        objClass.add("person");
        objClass.add("organizationalPerson");
        objClass.add("inetOrgPerson");
//        objClass.add("user");
        entry.put(objClass);


        try {

            // get a handle to an Initial DirContext
            DirContext context=connectionSource.getContext();

            context.createSubcontext("cn=" + primaryAttributeValue , entry);

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw  new IdentityStoreConnectorException("Error occured while adding Users to the Userstore", e);
        }
        return primaryAttributeValue;
    }

    @Override
    public Map<String, String> addUsers(Map<String, List<Attribute>> attributes) throws IdentityStoreConnectorException {
        IdentityStoreException identityStoreException = new IdentityStoreException();
        Map<String, String> userIdsToReturn = new HashMap<>();
        attributes.entrySet().stream().forEach(entry -> {
            try {
                String userId = addUser(entry.getValue());
                userIdsToReturn.put(entry.getKey(), userId);
            } catch (IdentityStoreConnectorException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw new IdentityStoreConnectorException("Error occured while adding Users to the Userstore");
        }
        return userIdsToReturn;
    }

    @Override
    public String updateUserAttributes(String userID, List<Attribute> attributes) throws IdentityStoreConnectorException {
        //PUT operation
        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String userIdentifierNew = userID;
        try {
            DirContext context=connectionSource.getContext();

        if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {

            String update_attr=DatabaseColumnNames.User.USER_UNIQUE_ID;
            ModificationItem[] mods = new ModificationItem[attributes.size()];

            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute(update_attr, primaryAttributeValue));

            // Perform the requested modifications on the named object
            context.modifyAttributes("uid = "+ primaryAttributeValue, mods);
            userIdentifierNew=primaryAttributeValue;
            attributes.remove(userIdentifierNew);

            int i=0;
            for (Attribute attribute : attributes) {
                if(attribute.getAttributeName()!=primaryAttributeValue) {
                    mods[i] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(attribute.getAttributeName(), attribute.getAttributeValue()));
                    i++;
                }
            }
        }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw  new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return primaryAttributeValue;
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1) throws IdentityStoreConnectorException {
        try {
            throw new IdentityStoreException(
                    "User store is operating in read only mode. Cannot write into the user store.");
        } catch (IdentityStoreException e) {
            throw  new IdentityStoreConnectorException();
        }
    }

    @Override
    public void deleteUser(String s) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list, List<String> list1) throws IdentityStoreConnectorException {

    }

    @Override
    public String addGroup(List<Attribute> list) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> map) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list, List<Attribute> list1) throws IdentityStoreConnectorException {
        return null;
    }

    @Override
    public void deleteGroup(String s) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list, List<String> list1) throws IdentityStoreConnectorException {

    }


    @Override
    public void removeAddedUsersInAFailure(List<String> list) throws IdentityStoreConnectorException {

    }

    @Override
    public void removeAddedGroupsInAFailure(List<String> list) throws IdentityStoreConnectorException {

    }


    private int getMaxRowRetrievalCount() {

        int length;

        String maxValue = identityStoreConfig.getProperties().get(LDAPConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;
    }

    private String escapeSpecialCharactersForFilterWithStarAsRegex(String dnPartial) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = properties
                .get(LDAPConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                    case '\\':
                        if (dnPartial.charAt(i + 1) == '*') {
                            sb.append("\\2a");
                            i++;
                            break;
                        }
                        sb.append("\\5c");
                        break;
                    case '(':
                        sb.append("\\28");
                        break;
                    case ')':
                        sb.append("\\29");
                        break;
                    case '\u0000':
                        sb.append("\\00");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    private String getFinalFilters(String filterPattern) throws IdentityStoreException {

        if (filterPattern.contains("?") || filterPattern.contains("**")) {
            throw new IdentityStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        properties.get(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.get(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.get(LDAPConstants.USER_NAME_ATTRIBUTE);

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.get(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);


        if (StringUtils.isNullOrEmptyAfterTrim(displayNameAttribute)) {

            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filterPattern)).append("))");
        } else {

            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filterPattern)).append("))");
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());

        }

        return finalFilter.toString();
    }

    protected NamingEnumeration<SearchResult> searchForUser(String searchFilter,
                                                            String[] returnedAtts,
                                                            DirContext dirContext)
            throws IdentityStoreException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchBases = LDAPConstants.USER_SEARCH_BASE;
        if (returnedAtts != null && returnedAtts.length > 0) {
            searchCtls.setReturningAttributes(returnedAtts);
        }

        if (log.isDebugEnabled()) {
            try {
                log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " +
                        dirContext.getNameInNamespace());
            } catch (NamingException e) {
                log.debug("Error while getting DN of search base", e);
            }
            if (returnedAtts == null) {
                log.debug("No attributes requested");
            } else {
                for (String attribute : returnedAtts) {
                    log.debug("Requesting attribute :" + attribute);
                }
            }
        }

        String[] searchBaseAraay = searchBases.split("#");
        NamingEnumeration<SearchResult> answer = null;

        try {
            for (String searchBase : searchBaseAraay) {
                answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    return answer;
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage = "Error occurred while search user for filter : " + searchFilter;

        } catch (NamingException e) {
            String errorMessage = "Error occurred while search user for filter : " + searchFilter;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }
        return answer;

    }

    protected NamingEnumeration<SearchResult> searchForGroup(String searchFilter,
                                                             String[] returnedAtts,
                                                             DirContext dirContext)
            throws IdentityStoreException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchBases = LDAPConstants.GROUP_SEARCH_BASE;
        if (returnedAtts != null && returnedAtts.length > 0) {
            searchCtls.setReturningAttributes(returnedAtts);
        }

        if (log.isDebugEnabled()) {
            try {
                log.debug("Searching for group with SearchFilter: " + searchFilter + " in SearchBase: " +
                        dirContext.getNameInNamespace());
            } catch (NamingException e) {
                log.debug("Error while getting DN of search base", e);
            }
            if (returnedAtts == null) {
                log.debug("No attributes requested");
            } else {
                for (String attribute : returnedAtts) {
                    log.debug("Requesting attribute :" + attribute);
                }
            }
        }

        String[] searchBaseAraay = searchBases.split("#");
        NamingEnumeration<SearchResult> answer = null;

        try {
            for (String searchBase : searchBaseAraay) {
                answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    return answer;
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage = "Error occurred while search group for filter : " + searchFilter;
            throw new IdentityStoreException(errorMessage, e);

        } catch (NamingException e) {
            String errorMessage = "Error occurred while search group for filter : " + searchFilter;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }
        return answer;

    }

    private String escapeDNForSearch(String dn) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = LDAPConstants.USER_LOGIN_STRING;

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        if (replaceEscapeCharacters) {
            return dn.replace("\\\\", "\\\\\\").replace("\\\"", "\\\\\"");
        } else {
            return dn;
        }


    }



}