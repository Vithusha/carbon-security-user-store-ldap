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

package org.wso2.carbon.security.userstore.ldap.test.osgi.store;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.bean.Group;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.ClaimManagerException;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.IdentityStore;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

/**
 * JDBC Identity store connector related tests.
 */
public class IdentityStoreTests extends StoreTests {


    public IdentityStoreTests() throws Exception {
        super();
    }

    @Test(priority = 24)
    public void testIsUserInGroupValid() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        assertTrue(identityStore.isUserInGroup(DEFAULT_USER_ID, DEFAULT_GROUP_ID));
    }

    @Test(priority = 25)
    public void testGetUserFromUsername() throws IdentityStoreException, UserNotFoundException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user = identityStore.getUser(DEFAULT_USERNAME);
        assertNotNull(user);
    }

//    @Test(priority = 26)
//    public void testGetUserFromUserId() throws IdentityStoreException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        assertNotNull(user);
//    }

    @Test(priority = 27)
    public void testListUsers() throws IdentityStoreException {

        String filterPattern = "*";
        MetaClaim metaClaim = new MetaClaim();
        metaClaim.setClaimURI("http://wso2.org/claims/username");
        metaClaim.setDialectURI("http://wso2.org/claims");

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.listUsers(metaClaim, filterPattern, 0, -1);

        assertFalse(users.isEmpty());
    }

    @Test(priority = 28)
    public void testGetUserAttributeValues() throws IdentityStoreException, UserNotFoundException,
            ClaimManagerException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Claim> claims = identityStore.getUser(DEFAULT_USER_ID).getClaims();

        assertFalse(claims.isEmpty());
    }

    @Test(priority = 29)
    public void testGetUserAttributeValuesFromAttributeNames() throws IdentityStoreException, UserNotFoundException,
            ClaimManagerException {

        List<String> attributeNames = new ArrayList<>();
        attributeNames.add("http://wso2.org/claims/username");
        attributeNames.add("http://wso2.org/claims/firstName");

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Claim> claims = identityStore.getUser(DEFAULT_USER_ID).getClaims();

        assertFalse(claims.isEmpty());
    }

//    @Test(priority = 30)
//    public void testGetClaims() throws IdentityStoreException, ClaimManagerException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        List<Claim> claims = user.getClaims();
//        assertTrue(claims != null && claims.size() > 0);
//    }

//    @Test(priority = 31)
//    public void testGetClaimsFromClaimURIs() throws IdentityStoreException, ClaimManagerException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        List<String> claimURIs = Arrays.asList("http://wso2.org/claims/firstName", "http://wso2.org/claims/lastName");
//        List<Claim> claims = user.getClaims(claimURIs);
//        assertTrue(claims != null && claims.size() == 2);
//    }

    @Test(priority = 32)
    public void testGetGroup() throws IdentityStoreException, GroupNotFoundException {

        IdentityStore identityStore = realmService.getIdentityStore();
        Group group = identityStore.getGroup(DEFAULT_GROUP);

        assertNotNull(group);
    }

//    @Test(priority = 33)
//    public void testGetGroupFromId() throws IdentityStoreException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        Group group = identityStore.getGroupFromId(DEFAULT_GROUP_ID, defaultDomain);
//
//        assertNotNull(group);
//    }

    @Test(priority = 34)
    public void testListGroups() throws IdentityStoreException {

        String filterPattern = "*";
        MetaClaim metaClaim = new MetaClaim();
        metaClaim.setClaimURI("http://wso2.org/claims/username");
        metaClaim.setDialectURI("http://wso2.org/claims");

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.listGroups(metaClaim, filterPattern, 0, -1);

        assertFalse(groups.isEmpty());
    }

    @Test(priority = 35)
    public void testGetGroupsOfUser() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.getGroupsOfUser(DEFAULT_USER_ID);
        assertFalse(groups.isEmpty());
    }

    @Test(priority = 36)
    public void testGetUsersOfGroup() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.getUsersOfGroup(DEFAULT_GROUP_ID);
        assertFalse(users.isEmpty());
    }
}
