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


import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.bean.Group;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnector;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConstants;
import org.wso2.carbon.userstore.ldap.datasource.utils.DatabaseColumnNames;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConnectionContext;
import org.wso2.carbon.userstore.ldap.internal.ConnectorDataHolder;
import sun.security.util.Length;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.sql.DataSource;
import java.util.*;


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
    protected Properties properties;


    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig) throws IdentityStoreException {

        this.properties = identityStoreConfig.getProperties();
        this.identityStoreId = identityStoreConfig.getConnectorId();
        this.identityStoreConfig = identityStoreConfig;


        try {
            connectionSource = new LDAPConnectionContext(properties);
            dataSource = ConnectorDataHolder.getInstance()
                    .getDataSource(properties.getProperty(LDAPConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new IdentityStoreException("Error occurred while initiating data source.", e);
        }


        if (log.isDebugEnabled()) {
            log.debug("LDAP identity store with id: {} initialized successfully.", identityStoreId);
        }

        //TODO check whether this is okay to be a property
        connectorUserId = identityStoreConfig.getProperties().getProperty("connectorUserId");
        connectorGroupId = identityStoreConfig.getProperties().getProperty("connectorGroupId");
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }

    @Override
    public String getConnectorUserId(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {
        return connectorUserId;
    }

    @Override
    public int getUserCount() throws IdentityStoreException {

        int count = 0;
        String searchFilter = "(objectClass=user)";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        try {
            DirContext context = connectionSource.getContext();

            //TODO : Check the searchbase functionality
            NamingEnumeration answer = context.search(LDAPConstants.USER_SEARCH_BASE, searchFilter, searchControls);
            while (answer.hasMore()) {
                SearchResult sr = (SearchResult) answer.next();
                ++count;
            }

        } catch (NamingException e) {
            throw new IdentityStoreException("An error occurred while getting user count.", e);
        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("An error occurred while getting user count. ", e);
        }
        return count;
    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }


        // We are using SQL filters. So replace the '*' with '%'.
        // filterPattern = filterPattern.replace('*', '%');

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

        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        } catch (NamingException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        }


        return userList;
    }

    @Override
    public List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern) throws
            IdentityStoreException {
        return getUserBuilderList(attributeName, filterPattern, 0, -1);
    }

    @Override
    public List<Attribute> getUserAttributeValues(String s) throws IdentityStoreException {
        Map<String, Integer> repetitions = new HashMap<>();
        return null;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userName, List<String> list) throws IdentityStoreException {
        String userAttributeSeparator = ",";
        String userDN = null;
        String[] propertyNames = new String[0];


        Map<String, String> values = new HashMap<String, String>();
        // if user name contains domain name, remove domain name
        String[] userNames = userName.split(LDAPConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }

        DirContext dirContext = null;
        try {
            dirContext = connectionSource.getContext();

        } catch (CredentialStoreException e) {
            throw new  IdentityStoreException("Error occured while creating datasource");
        }
        String  searchFilter = "(&(objectClass=user)(uid =" + userName + ")";;


        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        try {
            if (userDN != null) {
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                if (propertyNames != null && propertyNames.length > 0) {
                    searchCtls.setReturningAttributes(propertyNames);
                }
                if (log.isDebugEnabled()) {
                    try {
                        log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " +
                                dirContext.getNameInNamespace());
                    } catch (NamingException e) {
                        log.debug("Error while getting DN of search base", e);
                    }
                    if (propertyNames == null) {
                        log.debug("No attributes requested");
                    } else {
                        for (String attribute : propertyNames) {
                            log.debug("Requesting attribute :" + attribute);
                        }
                    }
                }
                try {
                    answer = dirContext.search(LDAPConstants.USER_SEARCH_BASE,searchFilter,searchCtls);
                } catch (PartialResultException e) {
                    // can be due to referrals in AD. so just ignore error
                    String errorMessage = "Error occurred while searching directory context for user : " + userDN +
                            " searchFilter : " + searchFilter;

                } catch (NamingException e) {
                    String errorMessage = "Error occurred while searching directory context for user : " + userDN +
                            " searchFilter : " + searchFilter;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }

                }
            } else {
                answer = this.searchForUser(searchFilter, propertyNames, dirContext);
            }
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                if (attributes != null) {
                    for (String name : propertyNames) {
                        if (name != null) {
                            Attribute attribute = (Attribute) attributes.get(name);
                            if (attribute != null) {
                                StringBuffer attrBuffer = new StringBuffer();
                                // TODO: Check with the line below.
                                for (attrs = attribute.getAll();
                                     attrs.hasMore(); ) {
                                    Object attObject = attrs.next();
                                    String attr = null;
                                    if (attObject instanceof String) {
                                        attr = (String) attObject;
                                    }


                                    String value = attrBuffer.toString();

                               /* *//**//*
                                 * Length needs to be more than userAttributeSeparator.length() for a valid
                                 * attribute, since we
                                            * attach userAttributeSeparator
                                            *//**//**/
                                    if (value != null && value.trim().length() > userAttributeSeparator.length()) {
                                        value = value.substring(0, value.length() - userAttributeSeparator.length());
                                        values.put(name, value);
                                    }

                                }
                            }
                        }
                    }
                }
            }
        }
        catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }

        //return values;
        return null;
    }

    @Override
    public Group.GroupBuilder getGroupBuilder(String attributeName, String filterPattern) throws GroupNotFoundException, IdentityStoreException {
        Group.GroupBuilder group=new Group.GroupBuilder();
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

        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        } catch (NamingException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        }

        return group;
    }

    @Override
    public int getGroupCount() throws IdentityStoreException {
        int count = 0;
        String searchFilter = "(objectClass=group)";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        try {
            DirContext context = connectionSource.getContext();

            //TODO : Check the searchbase functionality
            NamingEnumeration answer = context.search(LDAPConstants.USER_SEARCH_BASE, searchFilter, searchControls);
            while (answer.hasMore()) {
                SearchResult result = (SearchResult) answer.next();
                ++count;
            }

        } catch (NamingException e) {
            throw new IdentityStoreException("An error occurred while getting user count.", e);
        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("An error occurred while getting user count. ", e);
        }
        return count;
    }

    @Override
    public String getConnectorGroupId(String s, String s1) throws GroupNotFoundException, IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length) throws IdentityStoreException {
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }


        // We are using SQL filters. So replace the '*' with '%'.
        // filterPattern = filterPattern.replace('*', '%');

        List<Group.GroupBuilder> groupList = new ArrayList<>();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setCountLimit(length);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.User.USER_UNIQUE_ID});

        try {
            DirContext context = connectionSource.getContext();
            NamingEnumeration answer = context.search(DatabaseColumnNames.Group.GROUP_NAME, getFinalFilters(filterPattern), searchControls);
            while (answer.hasMore()) {
                String userUniqueId = answer.toString();
                groupList.add(new Group.GroupBuilder().setGroupId(userUniqueId));
            }

        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        } catch (NamingException e) {
            throw new IdentityStoreException("An error occurred while getting the user ", e);
        }


        return groupList;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String userName, List<String> attributeNames) throws IdentityStoreException {
        Map<String, Integer> repetitions = new HashMap<>();

        List<Attribute> attrValue= new ArrayList<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());

        Map<String, Integer> repetition = new HashMap<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());
       String[] attributeArray=new String[attributeNames.size()];
        attributeArray = attributeNames.toArray(attributeArray);
        String filter = "(&(objectClass=user)(uid =" + userName + ")";
        try {
            DirContext context=connectionSource.getContext();

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(attributeArray);


        } catch (CredentialStoreException e) {
            throw new IdentityStoreException("Error occured while retreiving Group Attribute values"+ e);
        }

    }

    @Override
    public List<Group.GroupBuilder> getGroupBuildersOfUser(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getUserBuildersOfGroup(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[]{DatabaseColumnNames.User.USER_UNIQUE_ID});
        boolean isUser=false;

        try {
            DirContext context = connectionSource.getContext();
            String filterPattern="(&(objectClass=user)("+DatabaseColumnNames.User.USER_UNIQUE_ID+"="+userId+ ") (memberof=CN="+groupId+",OU=Users))";
            NamingEnumeration answer = context.search(userId,filterPattern,searchControls);
            while (answer.hasMore()) {
                isUser=true;
            }
        } catch (CredentialStoreException e) {
            throw  new IdentityStoreException();
        } catch (NamingException e) {
            throw  new  IdentityStoreException();
        }

        return isUser;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return true;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    @Override
    public String addUser(List<Attribute> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public Map<String, String> addUsers(Map<String, List<Attribute>> map) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void deleteUser(String s) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list, List<String> list1) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public String addGroup(List<Attribute> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> map) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public String updateGroupAttributes(String s, List<Attribute> list, List<Attribute> list1) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void deleteGroup(String s) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list, List<String> list1) throws IdentityStoreException {
        throw new IdentityStoreException(
                "User store is operating in read only mode. Cannot write into the user store.");
    }


    private int getMaxRowRetrievalCount() {

        int length;

        String maxValue = identityStoreConfig.getProperties().getProperty(LDAPConstants.MAX_ROW_LIMIT);

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
                .getProperty(LDAPConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

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
                        properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.getProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);


        if (StringUtils.isEmpty(displayNameAttribute)) {

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
                log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
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

    private String escapeDNForSearch(String dn){
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
   /* public User.UserBuilder getUserBuilder(String filter, String s1) throws UserNotFoundException, IdentityStoreException {
        List<String> userNames = new ArrayList<>();

        int givenMax;
        int searchTime;

        try {
            givenMax =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = LDAPConstants.MAX_USER_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = LDAPConstants.MAX_SEARCH_TIME;
        }


        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(givenMax);
        searchCtls.setTimeLimit(searchTime);

        if (filter.contains("?") || filter.contains("**")) {
            throw new IdentityStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);

        String serviceNameAttribute = "sn";

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.getProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

        String[] returnedAtts;

        if (StringUtils.isNullOrEmptyAfterTrim(displayNameAttribute)) {
            returnedAtts =
                    new String[]{userNameProperty, serviceNameAttribute,
                            displayNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        } else {
            returnedAtts = new String[]{userNameProperty, serviceNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());

        }

        searchCtls.setReturningAttributes(returnedAtts);
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        List<String> list = new ArrayList<>();

        try {
            dirContext = connectionSource.getContext();
            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(LDAPConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {

                answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);
                while (answer.hasMoreElements()) {
                    SearchResult sr = answer.next();
                    if (sr.getAttributes() != null) {
                        log.debug("Result found ..");
                        Attribute attr = sr.getAttributes().get(userNameProperty);

                        // If this is a service principle, just ignore and
                        // iterate rest of the array. The entity is a service if
                        // value of surname is Service

                        Attribute attrSurname = sr.getAttributes().get(serviceNameAttribute);

                        if (attrSurname != null) {
                            if (log.isDebugEnabled()) {
                                log.debug(serviceNameAttribute + " : " + attrSurname);
                            }
                            String serviceName = (String) attrSurname.get();
                            if (serviceName != null
                                    && serviceName
                                    .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                                continue;
                            }
                        }

                        if (attr != null) {
                            String name = (String) attr.get();
                            list.add(name);
                        }
                    }
                }
            }

            userNames = list;


            if (log.isDebugEnabled()) {
                for (String username : userNames) {
                    log.debug("result: " + username);
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new IdentityStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter  ;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        } catch (CredentialStoreException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            throw new IdentityStoreException(errorMessage, e);
        }
        return null;

    }*/


/*





    @Override
    public void init(IdentityStoreConnectorConfig identityConnectorConfig) throws IdentityStoreException {

        this.identityConnectorConfig = identityConnectorConfig;
        this.properties = identityConnectorConfig.getProperties();
        // check if required configurations are in the user-mgt.xml
        new LDAPStoreConfig().checkRequiredUserStoreConfigurations();


        if (log.isDebugEnabled()) {
            log.debug("Initialization Started " + System.currentTimeMillis());
        }


        Hashtable env = new Hashtable(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=wso2,dc=com");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=wso2,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, "admin");


        try {

            this.connectionSource = new LDAPConnectionContext(properties);
            // Create initial context
            LdapContext ctx = new InitialLdapContext(env, null);
            System.out.println("Connection established");
            // Start TLS

            StartTlsResponse tls =
                    (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());


            tls.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            tls.negotiate();


            // Stop TLS
            tls.close();

            // Close the context when we're done


        } catch (NamingException e) {
            throw new IdentityStoreException();
        } catch (DataSourceException e) {
            throw new IdentityStoreException();
        } catch (IOException e) {
            throw new IdentityStoreException();
        }
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return properties.getProperty(identityStoreId);
    }

    @Override
    public User.UserBuilder getUserBuilder(String filter, String s1) throws UserNotFoundException, IdentityStoreException {
        List<String> userNames = new ArrayList<>();

        int givenMax;
        int searchTime;

        try {
            givenMax =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = LDAPConstants.MAX_USER_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = LDAPConstants.MAX_SEARCH_TIME;
        }


        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(givenMax);
        searchCtls.setTimeLimit(searchTime);

        if (filter.contains("?") || filter.contains("**")) {
            throw new IdentityStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);

        String serviceNameAttribute = "sn";

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.getProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

        String[] returnedAtts;

        if (StringUtils.isNullOrEmptyAfterTrim(displayNameAttribute)) {
            returnedAtts =
                    new String[]{userNameProperty, serviceNameAttribute,
                            displayNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        } else {
            returnedAtts = new String[]{userNameProperty, serviceNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());

        }

        searchCtls.setReturningAttributes(returnedAtts);
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        List<String> list = new ArrayList<>();

        try {
            dirContext = connectionSource.getContext();
            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(LDAPConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {

                answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);
                while (answer.hasMoreElements()) {
                    SearchResult sr = answer.next();
                    if (sr.getAttributes() != null) {
                        log.debug("Result found ..");
                        Attribute attr = sr.getAttributes().get(userNameProperty);

                        // If this is a service principle, just ignore and
                        // iterate rest of the array. The entity is a service if
                        // value of surname is Service

                        Attribute attrSurname = sr.getAttributes().get(serviceNameAttribute);

                        if (attrSurname != null) {
                            if (log.isDebugEnabled()) {
                                log.debug(serviceNameAttribute + " : " + attrSurname);
                            }
                            String serviceName = (String) attrSurname.get();
                            if (serviceName != null
                                    && serviceName
                                    .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                                continue;
                            }
                        }

                        if (attr != null) {
                            String name = (String) attr.get();
                            list.add(name);
                        }
                    }
                }
            }

            userNames = list;


            if (log.isDebugEnabled()) {
                for (String username : userNames) {
                    log.debug("result: " + username);
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new IdentityStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter  ;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        } catch (CredentialStoreException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            throw new IdentityStoreException(errorMessage, e);
        }
        return null;

    }


    public List<String> getUser(String filter, int maxItemLimit, int length)
            throws IdentityStoreException, CredentialStoreException {

        List<String> userNames = new ArrayList<>();

        if (maxItemLimit == 0) {
            return userNames;
        }

        int givenMax;
        int searchTime;

        try {
            givenMax =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = LDAPConstants.MAX_USER_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = LDAPConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit <= 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(maxItemLimit);
        searchCtls.setTimeLimit(searchTime);

        if (filter.contains("?") || filter.contains("**")) {
            throw new IdentityStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);

        String serviceNameAttribute = "sn";

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.getProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

        String[] returnedAtts;

        if (StringUtils.isNullOrEmptyAfterTrim(displayNameAttribute)) {
            returnedAtts =
                    new String[]{userNameProperty, serviceNameAttribute,
                            displayNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        } else {
            returnedAtts = new String[]{userNameProperty, serviceNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());
            log.debug("Search controls. Max Limit: " + maxItemLimit + " Max Time: " + searchTime);
        }

        searchCtls.setReturningAttributes(returnedAtts);
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        List<String> list = new ArrayList<>();

        try {
            dirContext = connectionSource.getContext();
            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(LDAPConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {

                answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);
                while (answer.hasMoreElements()) {
                    SearchResult sr = answer.next();
                    if (sr.getAttributes() != null) {
                        log.debug("Result found ..");
                        Attribute attr = sr.getAttributes().get(userNameProperty);

                        // If this is a service principle, just ignore and
                        // iterate rest of the array. The entity is a service if
                        // value of surname is Service

                        Attribute attrSurname = sr.getAttributes().get(serviceNameAttribute);

                        if (attrSurname != null) {
                            if (log.isDebugEnabled()) {
                                log.debug(serviceNameAttribute + " : " + attrSurname);
                            }
                            String serviceName = (String) attrSurname.get();
                            if (serviceName != null
                                    && serviceName
                                    .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                                continue;
                            }
                        }

                        if (attr != null) {
                            String name = (String) attr.get();
                            list.add(name);
                        }
                    }
                }
            }

            userNames = list;


            if (log.isDebugEnabled()) {
                for (String username : userNames) {
                    log.debug("result: " + username);
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter + "max limit : " + maxItemLimit;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new IdentityStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter + "max limit : " + maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }

        return userNames;
    }



    public User.UserBuilder getUser(Callback[] callbacks) throws UserNotFoundException, IdentityStoreException {

        for (Callback callback : callbacks)  {
            if (callback instanceof NameCallback) {
                String username = ((NameCallback) callback).getName();
                //return this.getUser(username);
                return null;

            }
        }

        throw new IdentityStoreException("No name callback present in the callback array.");
    }

    @Override
    public int getUserCount() throws IdentityStoreException {

        DirContext context= null;
        try {
            context = connectionSource.getContext();

        String searchFilter ="(objectClass=user)";
        SearchControls searchControls=new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration results=context.search(LDAPConstants.USER_SEARCH_BASE,searchFilter,searchControls);

        } catch (CredentialStoreException e) {
            e.printStackTrace();
        } catch (NamingException e) {
            e.printStackTrace();
        }
        return  0;
    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String filter, String s1, int i, int i1) throws IdentityStoreException {
        List<String> userNames = new ArrayList<>();

        int givenMax;
        int searchTime;

        try {
            givenMax =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = LDAPConstants.MAX_USER_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(properties.getProperty(LDAPConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = LDAPConstants.MAX_SEARCH_TIME;
        }
*//*
        if (maxItemLimit <= 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }
        *//*

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(givenMax);
        searchCtls.setTimeLimit(searchTime);

        if (filter.contains("?") || filter.contains("**")) {
            throw new IdentityStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);

        String serviceNameAttribute = "sn";

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                properties.getProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

        String[] returnedAtts;

        if (StringUtils.isNullOrEmptyAfterTrim(displayNameAttribute)) {
            returnedAtts =
                    new String[]{userNameProperty, serviceNameAttribute,
                            displayNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        } else {
            returnedAtts = new String[]{userNameProperty, serviceNameAttribute};
            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());

        }

        searchCtls.setReturningAttributes(returnedAtts);
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        List<String> list = new ArrayList<>();

        try {
            dirContext = connectionSource.getContext();
            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(LDAPConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {

                answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);
                while (answer.hasMoreElements()) {
                    SearchResult sr = answer.next();
                    if (sr.getAttributes() != null) {
                        log.debug("Result found ..");
                        Attribute attr = sr.getAttributes().get(userNameProperty);

                        // If this is a service principle, just ignore and
                        // iterate rest of the array. The entity is a service if
                        // value of surname is Service

                        Attribute attrSurname = sr.getAttributes().get(serviceNameAttribute);

                        if (attrSurname != null) {
                            if (log.isDebugEnabled()) {
                                log.debug(serviceNameAttribute + " : " + attrSurname);
                            }
                            String serviceName = (String) attrSurname.get();
                            if (serviceName != null
                                    && serviceName
                                    .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                                continue;
                            }
                        }

                        if (attr != null) {
                            String name = (String) attr.get();
                            list.add(name);
                        }
                    }
                }
            }

            userNames = list;


            if (log.isDebugEnabled()) {
                for (String username : userNames) {
                    log.debug("result: " + username);
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new IdentityStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter  ;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        } catch (CredentialStoreException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter ;
            throw new IdentityStoreException(errorMessage, e);
        }
        return null;
    }

    @Override
    public List<User.UserBuilder> getAllUserBuilderList(String s, String s1) throws IdentityStoreException {
        return null;
    }


    @Override
    public List<org.wso2.carbon.security.caas.user.core.bean.Attribute> getUserAttributeValues(String userName) throws IdentityStoreException {


        String userAttributeSeparator = ",";
        String userDN = null;
        String[] propertyNames = new String[0];


        Map<String, String> values = new HashMap<String, String>();
        // if user name contains domain name, remove domain name
        String[] userNames = userName.split(LDAPConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }

        DirContext dirContext = null;
        try {
            dirContext = connectionSource.getContext();

        } catch (CredentialStoreException e) {
            throw new  IdentityStoreException("Error occured while creating datasource");
        }
        String  searchFilter = "(&(objectClass=user)(uid =" + userName + ")";;


        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        try {
            if (userDN != null) {
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                if (propertyNames != null && propertyNames.length > 0) {
                    searchCtls.setReturningAttributes(propertyNames);
                }
                if (log.isDebugEnabled()) {
                    try {
                        log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
                    } catch (NamingException e) {
                        log.debug("Error while getting DN of search base", e);
                    }
                    if (propertyNames == null) {
                        log.debug("No attributes requested");
                    } else {
                        for (String attribute : propertyNames) {
                            log.debug("Requesting attribute :" + attribute);
                        }
                    }
                }
                try {
                    answer = dirContext.search(LDAPConstants.USER_SEARCH_BASE,searchFilter,searchCtls);
                } catch (PartialResultException e) {
                    // can be due to referrals in AD. so just ignore error
                    String errorMessage = "Error occurred while searching directory context for user : " + userDN + " searchFilter : " + searchFilter;

                } catch (NamingException e) {
                    String errorMessage = "Error occurred while searching directory context for user : " + userDN + " searchFilter : " + searchFilter;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }

                }
            } else {
                answer = this.searchForUser(searchFilter, propertyNames, dirContext);
            }
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                if (attributes != null) {
                    for (String name : propertyNames) {
                        if (name != null) {
                            Attribute attribute = attributes.get(name);
                            if (attribute != null) {
                                StringBuffer attrBuffer = new StringBuffer();
                                for (attrs = attribute.getAll(); attrs.hasMore(); ) {
                                    Object attObject = attrs.next();
                                    String attr = null;
                                    if (attObject instanceof String) {
                                        attr = (String) attObject;
                                    }


                                    String value = attrBuffer.toString();

                                *//*
                                 * Length needs to be more than userAttributeSeparator.length() for a valid
                                 * attribute, since we
                                 * attach userAttributeSeparator
                                 *//*
                                    if (value != null && value.trim().length() > userAttributeSeparator.length()) {
                                        value = value.substring(0, value.length() - userAttributeSeparator.length());
                                        values.put(name, value);
                                    }

                                }
                            }
                        }
                    }
                }
            }
        }
        catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }

        //return values;
        return null;



    }

    @Override
    public List<org.wso2.carbon.security.caas.user.core.bean.Attribute> getUserAttributeValues(String userName, List<String> list) throws IdentityStoreException {
        String userAttributeSeparator = ",";
        String userDN = null;
        String[] AttrArray = new String[list.size()];
        AttrArray=list.toArray(AttrArray);


        // read list of patterns from user-mgt.xml
        String patterns = properties.getProperty(LDAPConstants.USER_DN_PATTERN);

        if (patterns != null && !patterns.isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("Using User DN Patterns " + patterns);
            }

            if (patterns.contains(LDAPConstants.XML_PATTERN_SEPERATOR)) {
                try {
                    userDN = getNameInSpaceForUserName(userName);
                } catch (CredentialStoreException e) {
                    e.printStackTrace();
                }
            } else {
                userDN = MessageFormat.format(patterns, escapeSpecialCharactersForDN(userName));
            }
        }


        Map<String, String> values = new HashMap<>();
        DirContext dirContext = null;
        try {
            dirContext = this.connectionSource.getContext();
        } catch (CredentialStoreException e) {
            e.printStackTrace();
        }
        String userSearchFilter = properties.getProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        String searchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        try {
            if (userDN != null) {
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                if (list != null && list.size()> 0) {
                    searchCtls.setReturningAttributes(AttrArray);
                }
                try {
                    answer = dirContext.search(escapeDNForSearch(userDN), searchFilter, searchCtls);
                } catch (PartialResultException e) {
                    // can be due to referrals in AD. so just ignore error
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (isIgnorePartialResultException()) {
                        if (log.isDebugEnabled()) {
                            log.debug(errorMessage, e);
                        }
                    } else {
                        throw new IdentityStoreException(errorMessage, e);
                    }
                } catch (NamingException e) {
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new IdentityStoreException(errorMessage, e);
                }
            } else {
                answer = this.searchForUser(searchFilter,AttrArray, dirContext);
            }
            assert answer != null;
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                if (attributes != null) {
                    assert list != null;
                    for (String name : list) {
                        if (name != null) {
                            Attribute attribute = attributes.get(name);
                            if (attribute != null) {
                                StringBuilder attrBuffer = new StringBuilder();
                                for (attrs = attribute.getAll(); attrs.hasMore(); ) {
                                    Object attObject = attrs.next();
                                    String attr = null;
                                    if (attObject instanceof String) {
                                        attr = (String) attObject;
                                    }
                                    else if (attObject instanceof byte[]) {
                                        //if the attribute type is binary base64 encoded string will be returned
                                        attr = new String(Base64.getEncoder().encode((byte[]) attObject));
                                    }



                                    if (attr != null && attr.trim().length() > 0) {
                                        String attrSeparator = properties.getProperty(MULTI_ATTRIBUTE_SEPARATOR);
                                        if (attrSeparator != null && !attrSeparator.trim().isEmpty()) {
                                            userAttributeSeparator = attrSeparator;
                                        }
                                        attrBuffer.append(attr).append(userAttributeSeparator);
                                    }
                                    String value = attrBuffer.toString();

                                *//*
                                 * Length needs to be more than userAttributeSeparator.length() for a valid
                                 * attribute, since we
                                 * attach userAttributeSeparator
                                 *//*
                                    if (value.trim().length() > userAttributeSeparator.length()) {
                                        value = value.substring(0, value.length() - userAttributeSeparator.length());
                                        values.put(name, value);
                                    }

                                }
                            }
                        }
                    }
                }
            }

        } catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }

        }
        return (List<org.wso2.carbon.security.caas.user.core.bean.Attribute>) values;
    }

    @Override
    public Group.GroupBuilder getGroupBuilder(String groupID, String s1) throws GroupNotFoundException, IdentityStoreException {
        DirContext context= null;
        try {
            context = connectionSource.getContext();
        } catch (CredentialStoreException e) {
            e.printStackTrace();
        }


        String searchFilter = "(&(objectClass=group)(objectSid=" + groupID + "))";

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String ldapSearchBase=properties.getProperty(LDAPConstants.LDAP_SEARCH_BASE);
        NamingEnumeration<SearchResult> results = null;
        try {
            results = context.search(ldapSearchBase, searchFilter, searchControls);
        } catch (NamingException e) {
            throw new IdentityStoreException("Error occured while searc");
        }

        if(results.hasMoreElements()) {
            SearchResult searchResult = (SearchResult) results.nextElement();

            //make sure there is not another item available, there should be only 1 match
            if(results.hasMoreElements()) {
                System.err.println("Matched multiple groups for the group with SID: " + groupID);
                return null;
            } else {
                //return (String)searchResult.getAttributes();
                return new Group.GroupBuilder().setGroupId(groupID).setGroupId(groupID);
            }
        }

        return null;
    }






    public Group.GroupBuilder getGroup(String groupName) throws GroupNotFoundException, IdentityStoreException {




            List<Group.GroupBuilder> userList = new ArrayList<>();
            List<SearchResult> groupList=new ArrayList<>();


            String searchFilter = "(&(objectClass=user)" + groupName + ")";

            try {

                DirContext context= connectionSource.getContext();
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                NamingEnumeration<SearchResult> results = context.search(groupName, searchFilter, searchControls);


                SearchResult searchResult = null;

                if (results.hasMoreElements()) {
                    searchResult = (SearchResult) results.nextElement();
                    groupList.add(searchResult);
                    userList.add(new Group.GroupBuilder().setGroupId(String.valueOf(searchResult)));




                    if (results.hasMoreElements()) {
                        System.err.println("Multched multiple users with the same searchControl");
                    }
                }





            } catch (NamingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occured due to: ", e);
                }
            } catch (CredentialStoreException e) {
                e.printStackTrace();
            }

             return (Group.GroupBuilder) userList;
        }




    @Override
    public int getGroupCount() throws IdentityStoreException {
        return 0;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String s, int i, int i1) throws IdentityStoreException {
        return null;
    }


    public Group.GroupBuilder getGroup(String s,DirContext ctx) throws GroupNotFoundException, IdentityStoreException {

        NamingEnumeration results = null;
        try {

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String searchFilter= "(&(objectClass=user)(objectClass=group))";

            results = ctx.search("ou=path,dc=*,dc=*", "(objectClass=" + s + ")", controls);

            // Go through each item in list
            while (results.hasMore()) {
                SearchResult nc = (SearchResult) results.next();
                Attributes att = nc.getAttributes();
                String groupName = "Group Name " + att.get("cn").get(0);

            }
        } catch (NameNotFoundException e) {
            System.out.println("Error : " + e);

        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
        return null;

    }

    @Override
    public boolean isUserInGroup(String s, String s1) throws IdentityStoreException {
        return false;
    }

    public int getGroupCount(DirContext ctx) throws IdentityStoreException {

        int count = 0;
        NamingEnumeration results = null;
        try{
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String searchFilter="(&(objectClass = user)(objectClass = group))";
            results = ctx.search("ou=path,dc=*,dc=*", searchFilter,controls);

            while(results.hasMore()){
                SearchResult res = (SearchResult) results.next();
                Attributes attr = res.getAttributes();
                count ++;
            }
        }

        catch (NamingException e)

        {
            e.printStackTrace();
        }
        return count;
    }

    public List<Group.GroupBuilder> listGroups(String s, int i, int i1) throws IdentityStoreException {

        DirContext ctx = null;
        List<Group> groupList = new ArrayList<>();
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchFilter = "(objectClass=group)";

        try {
            NamingEnumeration results = ctx.search("ou=path,dc=*,dc=*",searchFilter,controls);

            while(results.hasMore()){
                SearchResult res = (SearchResult) results.next();
                Attributes attr = res.getAttributes();
                groupList.add((Group) attr);

            }

        } catch (NamingException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public List<org.wso2.carbon.security.caas.user.core.bean.Attribute> getGroupAttributeValues(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<org.wso2.carbon.security.caas.user.core.bean.Attribute> getGroupAttributeValues(String s, List<String> list) throws IdentityStoreException {

        try {
            DirContext context=connectionSource.getContext();
        } catch (CredentialStoreException e) {
            throw new IdentityStoreException();
        }

        Map<String, String> attrValues=new HashMap<>();
        attrValues.put(LDAPConstants.GROUP_NAME_ATTRIBUTE, String.valueOf(attrValues.size()));
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuildersOfUser(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getUserBuildersOfGroup(String s) throws IdentityStoreException {
        return null;
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
                log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
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
            String errorMessage ="Error occurred while search user for filter : " + searchFilter;

        } catch (NamingException e) {
            String errorMessage ="Error occurred while search user for filter : " + searchFilter;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new IdentityStoreException(errorMessage, e);
        }
        return answer;

    }



    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return true;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig()
    {
        return identityConnectorConfig;
    }

    private int getMaxRowRetrievalCount() {

        int length;
        String maxValue = identityConnectorConfig.getProperties().getProperty(LDAPConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;



    }

    private int getMaxRetreivalCount(){

        int length;
        String maxValue="";
        //String maxValue = identityConnectorConfig.getStoreProperties().getProperty(LDAPConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;


    }


    private String escapeDNForSearch(String dn){
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



    private String generateSearchFilter(String objectClass, String attrFilter) {
        return "(&(objectClass=" + objectClass + ")" + attrFilter + ")";
    }

    private String escapeSpecialCharactersForFilterWithStarAsRegex(String dnPartial) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = properties
                .getProperty(LDAPConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

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

    private boolean isIgnorePartialResultException() {

        return PROPERTY_REFERRAL_IGNORE.equals(userStoreProperties.get(LDAPConstants.PROPERTY_REFERRAL));
    }
    private String escapeSpecialCharactersForFilter(String dnPartial) {
        boolean replaceEscapeCharacters = true;
        dnPartial = dnPartial.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = properties
                .getProperty(LDAPConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

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
                        sb.append("\\5c");
                        break;
                    case '*':
                        sb.append("\\2a");
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

    private String escapeSpecialCharactersForDN(String text) {
        boolean replaceEscapeCharacters = true;
        text = text.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = properties
                .getProperty(LDAPConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

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
            if ((text.length() > 0) && ((text.charAt(0) == ' ') || (text.charAt(0) == '#'))) {
                sb.append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < text.length(); i++) {
                char currentChar = text.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\\\");
                        break;
                    case ',':
                        sb.append("\\,");
                        break;
                    case '+':
                        sb.append("\\+");
                        break;
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '<':
                        sb.append("\\<");
                        break;
                    case '>':
                        sb.append("\\>");
                        break;
                    case ';':
                        sb.append("\\;");
                        break;
                    case '*':
                        sb.append("\\2a");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            if ((text.length() > 1) && (text.charAt(text.length() - 1) == ' ')) {
                sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
            }
            if (log.isDebugEnabled()) {
                log.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }

    }
    private String getNameInSpaceForUserName(String userName) throws IdentityStoreException, CredentialStoreException {
        String searchBase;
        String userSearchFilter = properties.getProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        String userDNPattern = properties.getProperty(LDAPConstants.USER_DN_PATTERN);
        if (userDNPattern != null && userDNPattern.trim().length() > 0) {
            String[] patterns = userDNPattern.split(LDAPConstants.XML_PATTERN_SEPERATOR);
            for (String pattern : patterns) {
                searchBase = MessageFormat.format(pattern, escapeSpecialCharactersForDN(userName));
                String userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                // check in another DN pattern
                if (userDN != null) {
                    return userDN;
                }
            }
        }

        searchBase = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);

        return getNameInSpaceForUserName(userName, searchBase, userSearchFilter);

    }

    private String getNameInSpaceForUserName(String userName, String searchBase, String searchFilter)
            throws CredentialStoreException {;

        String userDN = null;

        DirContext dirContext = this.connectionSource.getContext();
        NamingEnumeration<SearchResult> answer = null;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            if (log.isDebugEnabled()) {
                try {
                    log.debug("Searching for user with SearchFilter: "
                            + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
                } catch (NamingException e) {
                    log.debug("Error while getting DN of search base", e);
                }
            }
            SearchResult userObj;
            String[] searchBases = searchBase.split(LDAPConstants.XML_PATTERN_SEPERATOR);
            for (String base : searchBases) {
                answer = dirContext.search(escapeDNForSearch(base), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    userObj = answer.next();
                    if (userObj != null) {
                        //no need to decode since , if decoded the whole string, can't be encoded again
                        //eg CN=Hello\,Ok=test\,test, OU=Industry
                        userDN = userObj.getNameInNamespace();
                        break;
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Name in space for " + userName + " is " + userDN);
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
        }
        return userDN;
    }
*/

}





