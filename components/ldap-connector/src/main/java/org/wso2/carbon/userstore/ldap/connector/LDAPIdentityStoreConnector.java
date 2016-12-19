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
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.*;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnector;
import org.wso2.carbon.identity.mgt.util.IdentityUserMgtUtil;
import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.userstore.ldap.datasource.utils.IdentityStoreConfigConstants;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConstants;
import org.wso2.carbon.userstore.ldap.datasource.utils.DatabaseAttributeNames;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConnectionContext;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * LDAP based implementation for identity store connector.
 */
public class LDAPIdentityStoreConnector implements IdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(LDAPIdentityStoreConnector.class);

    protected IdentityStoreConnectorConfig identityStoreConfig;
    protected String identityStoreId;
    protected String connectorUserId;
    protected String connectorGroupId;
    protected LDAPConnectionContext connectionSource = null;
    protected Map<String, String> properties;


    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreConnectorException {
 //TODO: Add other parameters to the config
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

        }

        connectorUserId = identityStoreConfig.getProperties().get("connectorUserId");
        connectorGroupId = identityStoreConfig.getProperties().get("connectorGroupId");
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }


    @Override
    public int getUserCount() throws IdentityStoreConnectorException {


        int count = 0;
        String searchFilter = IdentityStoreConfigConstants.usernameListFilter;
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        try {
           DirContext context=  connectionSource.getContext();

            NamingEnumeration answer = context.search("", searchFilter, searchControls);
            while (answer.hasMore()) {

                ++count;
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occurred while getting user count.", e);
        }
        return count;
    }



    @Override
    public List<Attribute> getUserAttributeValues(String userName) throws IdentityStoreConnectorException {
        DirContext context;
        List<Attribute> attributeList = new ArrayList<>();
        try {
            context = connectionSource.getContext();
            Attributes attrs = context.getAttributes("cn=" + userName);
            for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
                String[] attr_pair = (ae.next().toString().split(":"));
                String name = attr_pair[0];
                String value = attr_pair[1];
                Attribute attribute = new Attribute();
                attribute.setAttributeName(name);
                attribute.setAttributeValue(value);
                attributeList.add(attribute);
            }
            return attributeList;
        } catch (NamingException | CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occured while getting the user Attributes ", e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userName, List<String> attributeNames)
            throws IdentityStoreConnectorException {
        Map<String, Integer> repetitions = new HashMap<>();

        List<Attribute> userAttributes = new ArrayList<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());

        Map<String, Integer> repetition = new HashMap<>();
        repetitions.put(LDAPConstants.ATTRIBUTE_NAMES, attributeNames.size());
        String[] attributeArray = new String[attributeNames.size()];
        attributeArray = attributeNames.toArray(attributeArray);
        String filter = IdentityStoreConfigConstants.usernameListFilter;
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

//
//    public Group.GroupBuilder getGroupBuilder(String attributeName, String filterPattern) throws GroupNotFoundException,
//            IdentityStoreException {
//        Group.GroupBuilder group = new Group.GroupBuilder();
//        SearchControls searchControls = new SearchControls();
//        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//        searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.Group.GROUP_UNIQUE_ID});
//
//        try {
//            DirContext context = connectionSource.getContext();
//            NamingEnumeration answer = context.search(attributeName, getFinalFilters(filterPattern), searchControls);
//            while (answer.hasMore()) {
//                String groupUniqueId = answer.toString();
//                group.setGroupId(groupUniqueId);
//            }
//
//        } catch (NamingException|CredentialStoreConnectorException e) {
//            throw new IdentityStoreException("An error occurred while getting the user ", e);
//        }
//
//        return group;
//    }

    @Override
    public int getGroupCount() throws IdentityStoreConnectorException {
        int count = 0;
        String searchFilter = IdentityStoreConfigConstants.groupNameListFilter;
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
    public List<Attribute> getGroupAttributeValues(String groupName) throws IdentityStoreConnectorException {
        DirContext context;
        List<String> attr_list = new ArrayList<>();
        try {
            context = connectionSource.getContext();
            Attributes attrs = context.getAttributes("(&(objectClass=user)(ou=" + groupName);
            for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); ) {
                attr_list.add((String) ae.next());
            }


            return getGroupAttributeValues(groupName, attr_list);

         } catch (NamingException|IdentityStoreConnectorException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("An error occured while getting the group Attributes ", e);
        }
    }


    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames) throws
            IdentityStoreConnectorException {


        List<Attribute> userAttributes = new ArrayList<>();
        String[] attributeArray = new String[attributeNames.size()];
        attributeArray = attributeNames.toArray(attributeArray);
        String filter=IdentityStoreConfigConstants.groupNameSearchFilter;
        filter.replaceAll("[?]",groupId);
        try {
            DirContext context = connectionSource.getContext();

//            SearchControls searchControls = new SearchControls();
//            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//            searchControls.setReturningAttributes(attributeArray);

//            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.groupSearchBase,
//                    filter, searchControls);

            NamingEnumeration<SearchResult> answer =searchForGroup(filter,attributeArray,context);




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
                        groupId, identityStoreId);
            }

            return userAttributes;


        } catch (NamingException|CredentialStoreConnectorException|IdentityStoreException e) {
            throw new IdentityStoreConnectorException("Error occured while retreiving Group Attribute values" + e);
        }

    }


    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreConnectorException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.User.USER_UNIQUE_ID});
        boolean isUser = false;

        try {
            DirContext context = connectionSource.getContext();
            String filterPattern = "(&(objectClass=user)(" + DatabaseAttributeNames.User.USER_UNIQUE_ID + "="
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
        return false;
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

            throw new IdentityStoreConnectorException("Primary Attribute " + connectorUserId +
                    " is not found among the " + "attribute list");
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
        ;
        BasicAttribute objClass = new BasicAttribute("objectClass");

        objClass.add("top");
        objClass.add("person");
        objClass.add("organizationalPerson");
        objClass.add("inetOrgPerson");

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
    public Map<String, String> addUsers(Map<String, List<Attribute>> attributes)
            throws IdentityStoreConnectorException {
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
    public String updateUserAttributes(String userID, List<Attribute> attributes)
            throws IdentityStoreConnectorException {
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


            ModificationItem[] mods = new ModificationItem[attributes.size()];

            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute(userID, primaryAttributeValue));

            // Perform the requested modifications on the named object

            context.modifyAttributes("cn="+primaryAttributeValue, mods);
            userIdentifierNew=primaryAttributeValue;
            attributes.remove(userIdentifierNew);

            int i=0;
            for (Attribute attribute : attributes) {
                if(attribute.getAttributeName()!=primaryAttributeValue) {
                    mods[i] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                            new BasicAttribute(attribute.getAttributeName(), attribute.getAttributeValue()));
                    i++;
                }
            }
        }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw  new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return userIdentifierNew;
    }

    @Override
    public String updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1)
            throws IdentityStoreConnectorException {
        try {
            throw new IdentityStoreException(
                    "User store is operating in read only mode. Cannot write into the user store.");
        } catch (IdentityStoreException e) {
            throw  new IdentityStoreConnectorException();
        }
    }

    @Override
    public void deleteUser(String userId) throws IdentityStoreConnectorException {

    try{

        DirContext context = connectionSource.getContext();
        context.unbind("cn =" +userId);

    } catch (CredentialStoreConnectorException e) {
        throw  new IdentityStoreConnectorException("Error occured while creating the connection", e);
    } catch (NamingException e) {
       throw new IdentityStoreConnectorException("User cannot be found in the userstore" , e);
    }

    }


    @Override
    public String addGroup(List<Attribute> attributes) throws IdentityStoreConnectorException {

        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);
        BasicAttribute attr;
        BasicAttributes entry = new BasicAttributes();
        int i = 0;
        for (Attribute attribute : attributes) {

            String name = attribute.getAttributeName();
            String value = attribute.getAttributeValue();
            attr = new BasicAttribute(name, value);
            entry.put(attr);

        }

        BasicAttribute objclass = new BasicAttribute("objectClass");


        objclass.add("top");
        objclass.add("organizationalUnit");

        entry.put(objclass);


        try {

            // get a handle to an Initial DirContext
            DirContext context = connectionSource.getContext();

            context.createSubcontext("ou=" + primaryAttributeValue, entry);

        } catch (NamingException | CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occured while adding the group to the Userstore", e);
        }
        return  primaryAttributeValue;
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> attributes) throws IdentityStoreConnectorException {
        IdentityStoreConnectorException identityStoreException = new IdentityStoreConnectorException();
        Map<String, String> groupIdsToReturn = new HashMap<>();
        attributes.entrySet().stream().forEach(entry -> {
            try {
                String groupId = addGroup(entry.getValue());
                groupIdsToReturn.put(entry.getKey(), groupId);
            } catch (IdentityStoreConnectorException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
        return groupIdsToReturn;
    }

    @Override
    public void updateGroupsOfUser(String groupIdentifier, List<String> users) throws IdentityStoreConnectorException {
        String filter = IdentityStoreConfigConstants.groupNameListFilter;
        filter.replaceAll("[?]", groupIdentifier);

        DirContext context = null;
        try {
            context = connectionSource.getContext();

            for(String user : users) {
                ModificationItem[] roleMods = new ModificationItem[]
                        {
                                new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute
                                        (IdentityStoreConfigConstants.groupNameAttribute, user))
                        };
                context.modifyAttributes(groupIdentifier, roleMods);

            }

        } catch (CredentialStoreConnectorException|NamingException e) {
            throw  new IdentityStoreConnectorException("Error occured while updating users to the Group" , e);
        }
    }

    @Override
    public void updateGroupsOfUser(String userIdentifier, List<String> groupIdentifiersToAdd,
                                   List<String> groupIdentifiersToRemove)
            throws IdentityStoreConnectorException {

    }

    public String addGroups(List<Attribute> attributes) throws IdentityStoreConnectorException {

        String connectorUniqueId = IdentityUserMgtUtil.generateUUID();

            String primaryAttributeValue = attributes.stream()
                    .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                    .map(attribute -> attribute.getAttributeValue())
                    .findFirst()
                    .orElse(null);

            if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {

                throw new IdentityStoreConnectorException("Primary Attribute " + connectorUserId +
                        " is not found among the " + "attribute list");
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

            objClass.add("top");
            objClass.add("groupOfUniqueNames");
            objClass.add("groupOfForethoughtNames");

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
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributes) throws IdentityStoreConnectorException {
        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String userIdentifierNew = groupIdentifier;
        try {
            DirContext context=connectionSource.getContext();

            if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
                ModificationItem[] mods = new ModificationItem[attributes.size()];

                mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                        new BasicAttribute(groupIdentifier, primaryAttributeValue));

                String name = IdentityStoreConfigConstants.usernameSearchFilter.replaceAll("[?]" , groupIdentifier);
                // Perform the requested modifications on the named object

                context.modifyAttributes( name , mods);
                userIdentifierNew=primaryAttributeValue;
                attributes.remove(userIdentifierNew);

                int i=0;
                for (Attribute attribute : attributes) {
                    if(attribute.getAttributeName()!=primaryAttributeValue) {
                        mods[i] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                                new BasicAttribute(attribute.getAttributeName(), attribute.getAttributeValue()));
                        i++;
                    }
                }
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw  new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return userIdentifierNew;
    }

    @Override
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributesToAdd,
                                        List<Attribute> attributesToRemove) throws IdentityStoreConnectorException {
        //PATCH operation

        // Fetch the existing attributes of the user
        List<Attribute> currentAttributes = getUserAttributeValues(groupIdentifier);

        // Filter the attributes to add and update
        // If the same attribute is present in the database already, update the value.

        Map<Boolean, List<Attribute>> attributeFilteredMap = attributesToAdd.stream()
                .collect(Collectors.partitioningBy(a -> currentAttributes.parallelStream().anyMatch(ca -> ca
                        .getAttributeName().equals(a.getAttributeName()))));

        List<Attribute> filteredAttributesToAdd = attributeFilteredMap.get(false);
        List<Attribute> filteredAttributesToUpdate = attributeFilteredMap.get(true);
        {
            return null;
        }
    }
    @Override
    public void deleteGroup(String connectorGroupId) throws IdentityStoreConnectorException {

        String groupName=IdentityStoreConfigConstants.groupNameSearchFilter.replaceAll("[?]",connectorGroupId);
        try{

            DirContext context = connectionSource.getContext();
            context.unbind(groupName);

        } catch (CredentialStoreConnectorException e) {
            throw  new IdentityStoreConnectorException("Error occured while creating the connection", e);
        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("User cannot be found in the userstore" , e);
        }
    }

    @Override
    public void updateUsersOfGroup(String connectorGroupId, List<String> list) throws IdentityStoreConnectorException {

        String filter= LDAPConstants.GROUP_NAME_LIST_FILTER.replaceAll("[?]", connectorUserId);
        SearchControls searchControls=new SearchControls();
        searchControls.setReturningAttributes(new String[]{connectorUserId});


    }

    @Override
    public void updateUsersOfGroup(String groupIdentifier, List<String> userIdentifiersToAdd,
                                   List<String> userIdentifiersToRemove)
            throws IdentityStoreConnectorException {

    }


    @Override
    public void removeAddedUsersInAFailure(List<String> connectorUserIds) throws IdentityStoreConnectorException {
        try {
            DirContext context = connectionSource.getContext();
            for (String userId : connectorUserIds) {
                deleteUser(userId, context);
            }
        } catch (CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error while establishing the connection", e);
        }
    }

    @Override
    public void removeAddedGroupsInAFailure(List<String> connectorGroupIds) throws IdentityStoreConnectorException {
        try {
            DirContext context = connectionSource.getContext();
            for (String userId : connectorGroupIds) {
                deleteUser(userId, context);
            }
        } catch (CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error while establishing the connection", e);
        }
    }

    @Override
    public String getConnectorUserId(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreConnectorException {
        String filter="(&("+attributeName + "=" + attributeValue + "))";
        String userId;

        try {
            DirContext context = connectionSource.getContext();

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.User.USER_UNIQUE_ID});

            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.userSearchBase,
                    filter, searchControls);

            if (answer.hasMore()) {
               userId = answer.next().getAttributes().toString();
                return  userId;
            }

            else {
                throw new UserNotFoundException("User not found with the given attribute");
            }

        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occured while retreiving Group Attribute values" + e);
        }

    }





    @Override
    public List<String> listConnectorUserIds(String attributeName, String attributeValue, int startIndex, int length)
            throws IdentityStoreConnectorException {

        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.

        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        String filter="(&("+attributeName + "=" + attributeValue + "))";
        String userId;

        List<String> users = new ArrayList<>();
        try {
            DirContext context=connectionSource.getContext();

            SearchControls searchControls=new SearchControls();
            searchControls.setCountLimit(length);
            searchControls.setSearchScope(startIndex);
            searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.Group.GROUP_UNIQUE_ID});

            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.groupSearchBase,
                    filter, searchControls);

            if (answer.hasMore()) {
                userId = answer.next().getAttributes().toString();
                users.add(userId);

            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", users.size(),
                        attributeValue, identityStoreId);
            }
        }

        catch (CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        }


        return users;
    }



    @Override
    public String getConnectorGroupId(String attributeName, String attributeValue) throws GroupNotFoundException,
            IdentityStoreConnectorException {


        String filter="(&("+attributeName + "=" + attributeValue + "))";
        String groupId;

        try {
            DirContext context = connectionSource.getContext();

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.Group.GROUP_UNIQUE_ID});

            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.groupSearchBase,
                    filter, searchControls);


            if (answer.hasMore()) {
                 groupId = answer.next().getAttributes().toString();
                return  groupId;
            }
            else {
                throw new GroupNotFoundException("User not found with the given attribute");
            }


        } catch (NamingException|CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occured while retreiving Group Attribute values" + e);
        }

    }

    @Override
    public List<String> listConnectorGroupIds(String attributeName, String attributeValue, int startIndex, int length)
            throws IdentityStoreConnectorException {
        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        String filter="(&("+attributeName + "=" + attributeValue + "))";
        String groupId;

        List<String> groups = new ArrayList<>();
        try {
            DirContext context=connectionSource.getContext();

            SearchControls searchControls=new SearchControls();
            searchControls.setCountLimit(length);
            searchControls.setSearchScope(startIndex);
            searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.Group.GROUP_UNIQUE_ID});

            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.groupSearchBase,
                    filter, searchControls);

            if (answer.hasMore()) {
                groupId = answer.next().getAttributes().toString();
                groups.add(groupId);

            }

        if (log.isDebugEnabled()) {
            log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
                    attributeValue, identityStoreId);
        }
        }

        catch (CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        }


        return groups;
    }

    @Override
    public List<String> listConnectorGroupIdsByPattern(String attributeName, String filterPattern, int startIndex, int
            length)
            throws IdentityStoreConnectorException {

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }


        List<String> groups = new ArrayList<>();
        try {
            filterPattern = getFinalFilters(filterPattern);

            String filter="(&("+attributeName + "=" + filterPattern + "))";
            String groupId;
            DirContext context=connectionSource.getContext();

            SearchControls searchControls=new SearchControls();
            searchControls.setCountLimit(length);
            searchControls.setSearchScope(startIndex);
            searchControls.setReturningAttributes(new String[]{DatabaseAttributeNames.Group.GROUP_UNIQUE_ID});

            NamingEnumeration<SearchResult> answer = context.search(IdentityStoreConfigConstants.groupSearchBase,
                    filter, searchControls);

            if (answer.hasMore()) {
                groupId = answer.next().getAttributes().toString();
                groups.add(groupId);

            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
                        filterPattern, identityStoreId);
            }
        }

        catch (CredentialStoreConnectorException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        } catch (IdentityStoreException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list." + e);
        }


        return groups;
    }
    @Override
    public List<String> listConnectorUserIdsByPattern(String attributeName, String filterPattern, int startIndex, int
            length)
            throws IdentityStoreConnectorException {
        return null;
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

        String[] searchBaseArray = searchBases.split("#");
        NamingEnumeration<SearchResult> answer = null;

        try {
            for (String searchBase : searchBaseArray) {
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

    public void deleteUser(String userId , DirContext context) throws IdentityStoreConnectorException {

        String username=IdentityStoreConfigConstants.usernameSearchFilter.replaceAll("[?]", userId);
        try{
            context.unbind(username);

        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("User cannot be found in the userstore" , e);
        }

    }

    public void deleteGroup(String connectorGroupId, DirContext context) throws IdentityStoreConnectorException {

        String groupName = IdentityStoreConfigConstants.groupNameSearchFilter.replaceAll("[?]", connectorGroupId);
        try {

            context.unbind(groupName);

        } catch (NamingException e) {
            throw new IdentityStoreConnectorException("User cannot be found in the userstore", e);
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
}