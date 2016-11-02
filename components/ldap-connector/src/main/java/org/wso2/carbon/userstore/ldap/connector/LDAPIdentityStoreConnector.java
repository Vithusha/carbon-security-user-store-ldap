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

import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;

import java.util.List;
import java.util.Map;

/**
 * LDAP based implementation for identity store connector.
 */
public class LDAPIdentityStoreConnector implements IdentityStoreConnector {

    @Override
    public void init(String s, IdentityStoreConfig identityStoreConfig) throws IdentityStoreException {

    }

    @Override
    public String getIdentityStoreId() {
        return null;
    }

    @Override
    public User.UserBuilder getUserFromId(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public User.UserBuilder getUser(String s) throws UserNotFoundException, IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> listUsers(String s, int i, int i1) throws IdentityStoreException {
        return null;
    }

    @Override
    public Map<String, String> getUserAttributeValues(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public Map<String, String> getUserAttributeValues(String s, List<String> list) throws IdentityStoreException {
        return null;
    }

    @Override
    public Group.GroupBuilder getGroupById(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public Group.GroupBuilder getGroup(String s) throws GroupNotFoundException, IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> listGroups(String s, int i, int i1) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupsOfUser(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getUsersOfGroup(String s) throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String s, String s1) throws IdentityStoreException {
        return false;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return false;
    }

    @Override
    public IdentityStoreConfig getIdentityStoreConfig() {
        return null;
    }
}
