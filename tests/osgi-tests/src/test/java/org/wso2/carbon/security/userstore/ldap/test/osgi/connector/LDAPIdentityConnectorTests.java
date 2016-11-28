package org.wso2.carbon.security.userstore.ldap.test.osgi.connector;

import org.ops4j.pax.exam.util.Filter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnector;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.ldap.test.osgi.LDAPConnectorTests;
import org.wso2.carbon.userstore.ldap.connector.factory.LDAPIdentityStoreConnectorFactory;

import javax.inject.Inject;
import javax.naming.Context;
import java.util.Properties;

/**
 * Created by wso2 on 11/8/16.
 */
public class LDAPIdentityConnectorTests extends LDAPConnectorTests {

    @Inject
    @Filter("(connector-type=LDAPIdentityStore)")
    protected IdentityStoreConnectorFactory identityStoreConnectorFactory;

    private static IdentityStoreConnector identityStoreConnector;

    private void initConnector() throws IdentityStoreException {
        Assert.assertNotNull(identityStoreConnectorFactory);
        Assert.assertTrue(identityStoreConnectorFactory instanceof LDAPIdentityStoreConnectorFactory);
        identityStoreConnector = identityStoreConnectorFactory.getConnector();
        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
        identityStoreConnectorConfig.setConnectorId("LDAPIS1");
        identityStoreConnectorConfig.setConnectorType("LDAPPrivilegedIdentityStore");
        identityStoreConnectorConfig.setDomainName("carbon");
//        List<String> uniqueAttributes = new ArrayList<>();
//        uniqueAttributes.add("username");
//        uniqueAttributes.add("email");
//        identityStoreConnectorConfig.setUniqueAttributes(uniqueAttributes);
//        List<String> otherAttributes = new ArrayList<>();
//        otherAttributes.add("firstName");
//        otherAttributes.add("lastName");
//        identityStoreConnectorConfig.setOtherAttributes(otherAttributes);
        Properties properties = new Properties();
        properties.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.setProperty(Context.PROVIDER_URL, "ldap://localhost:389/dc=wso2,dc=com");
        properties.setProperty(Context.SECURITY_PRINCIPAL, "cn=admin,dc=wso2,dc=com");
        properties.setProperty(Context.SECURITY_CREDENTIALS, "admin");
        properties.setProperty(Context.SECURITY_AUTHENTICATION,"simple");
        properties.setProperty("connectorUserId", "username");
        properties.setProperty("connectorGroupId", "groupname");
        identityStoreConnectorConfig.setProperties(properties);
        identityStoreConnector.init(identityStoreConnectorConfig);
    }

    @Test(priority = 2)
    public void testAddUser() throws IdentityStoreException, IdentityStoreConnectorException {

        //As beforeClass is not supported, connector is initialized here
          initConnector();

//        List<Attribute> attributes = new ArrayList<>();
//        Attribute attribute1 = new Attribute();
//        attribute1.setAttributeName("username");
//        attribute1.setAttributeValue("maduranga");
//        attributes.add(attribute1);
//        Attribute attribute2 = new Attribute();
//        attribute2.setAttributeName("email");
//        attribute2.setAttributeValue("maduranga@wso2.com");
//        attributes.add(attribute2);
//        Attribute attribute3 = new Attribute();
//        attribute3.setAttributeName("firstname");
//        attribute3.setAttributeValue("Maduranga");
//        attributes.add(attribute3);
//        Attribute attribute4 = new Attribute();
//        attribute4.setAttributeName("lastname");
//        attribute4.setAttributeValue("Siriwardena");
//        attributes.add(attribute4);
//
//        identityStoreConnector.addUser(attributes);

        int attributesRetrieved = identityStoreConnector.getGroupCount();
//
//        Assert.assertNotNull(attributesRetrieved);
//        Assert.assertTrue(attributesRetrieved.size() == 4);
//        Map<String, String> attributeMap = new HashMap<>();
//        for (Attribute attribute : attributesRetrieved) {
//            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
//        }
//        Assert.assertEquals(attributeMap.get("username"), "maduranga");
//        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
//        Assert.assertEquals(attributeMap.get("firstname"), "Maduranga");
//        Assert.assertEquals(attributeMap.get("lastname"), "Siriwardena");
    }

//    @Test(priority = 3)
//    public void testAddGroup() throws IdentityStoreException {
//
////        List<Attribute> attributes = new ArrayList<>();
////        Attribute attribute1 = new Attribute();
////        attribute1.setAttributeName("groupname");
////        attribute1.setAttributeValue("engineering");
////        attributes.add(attribute1);
////        Attribute attribute2 = new Attribute();
////        attribute2.setAttributeName("reportsto");
////        attribute2.setAttributeValue("director@wso2.com");
////        attributes.add(attribute2);
////
////        identityStoreConnector.addGroup(attributes);
//
//        List<Attribute> attributeRetrieved = identityStoreConnector.getGroupAttributeValues("engineering");
//        Assert.assertNotNull(attributeRetrieved);
//        Assert.assertEquals(attributeRetrieved.size(), 2);
//    }
//
//    @Test(priority = 4)
//    public void testGroupsOfUserPut() throws IdentityStoreException {
//
////        List<String> groups = new ArrayList();
////        groups.add("engineering");
////
////        identityStoreConnector.updateGroupsOfUser("maduranga", groups);
//        List<Group.GroupBuilder> groupBuilders = identityStoreConnector.getGroupBuildersOfUser("maduranga");
//        Assert.assertEquals(groupBuilders.size(), 1);
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "engineering"));
//
////        groups = new ArrayList();
////        //These groups are added from the test data set
////        groups.add("is");
////        groups.add("sales");
////
////        identityStoreConnector.updateGroupsOfUser("maduranga", groups);
//
//        groupBuilders = identityStoreConnector.getGroupBuildersOfUser("maduranga");
//        Assert.assertEquals(groupBuilders.size(), 2);
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "is"));
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "sales"));
//    }
//
//    @Test(priority = 5)
//    public void testGroupsOfUserPatch() throws IdentityStoreException {
//
////        List<String> groupsToAdd = new ArrayList();
////        groupsToAdd.add("engineering");
////
////        List<String> groupsToRemove = new ArrayList();
////        groupsToRemove.add("sales");
////
////        identityStoreConnector.updateGroupsOfUser("maduranga", groupsToAdd, groupsToRemove);
//
//        List<Group.GroupBuilder> groupBuilders = identityStoreConnector.getGroupBuildersOfUser("maduranga");
//
//        Assert.assertEquals(groupBuilders.size(), 2);
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "is"));
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "engineering"));
//    }
//
//    @Test(priority = 6)
//    public void testUsersOfGroupPut() throws IdentityStoreException {
//
////        List<String> users = new ArrayList();
////        users.add("darshana");
////        users.add("thanuja");
////
////        identityStoreConnector.updateUsersOfGroup("engineering", users);
//
//        List<User.UserBuilder> groupBuilders = identityStoreConnector.getUserBuildersOfGroup("engineering");
//
//        Assert.assertEquals(groupBuilders.size(), 2);
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("darshana", "engineering"));
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("thanuja", "engineering"));
//    }
//
//    @Test(priority = 7)
//    public void testUsersOfGroupPatch() throws IdentityStoreException {
//
////        List<String> usersToAdd = new ArrayList();
////        usersToAdd.add("maduranga");
////
////        List<String> usersToRemove = new ArrayList();
////        usersToRemove.add("darshana");
////
////        identityStoreConnector.updateUsersOfGroup("engineering", usersToAdd, usersToRemove);
//
//        List<User.UserBuilder> groupBuilders = identityStoreConnector.getUserBuildersOfGroup("engineering");
//
//        Assert.assertEquals(groupBuilders.size(), 2);
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("thanuja", "engineering"));
//        Assert.assertTrue(identityStoreConnector.isUserInGroup("maduranga", "engineering"));
//    }
//
//    @Test(priority = 8)
//    public void testUpdateUserAttributesPut() throws IdentityStoreException {
//
////        List<Attribute> attributesToUpdate = new ArrayList();
////        Attribute attribute1 = new Attribute();
////        attribute1.setAttributeName("username");
////        attribute1.setAttributeValue("maduranga1");
////        attributesToUpdate.add(attribute1);
////        Attribute attribute2 = new Attribute();
////        attribute2.setAttributeName("email");
////        attribute2.setAttributeValue("maduranga1@wso2.com");
////        attributesToUpdate.add(attribute2);
////        Attribute attribute3 = new Attribute();
////        attribute3.setAttributeName("firstname");
////        attribute3.setAttributeValue("Maduranga1");
////        attributesToUpdate.add(attribute3);
////
////        identityStoreConnector.updateUserAttributes("maduranga", attributesToUpdate);
//
//        List<Attribute> attributesRetrieved = identityStoreConnector.getUserAttributeValues("maduranga1");
//
//        Assert.assertEquals(attributesRetrieved.size(), 3);
//
//        Map<String, String> attributeMap = new HashMap<>();
//        for (Attribute attribute : attributesRetrieved) {
//            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
//        }
//        Assert.assertEquals(attributeMap.get("username"), "maduranga1");
//        Assert.assertEquals(attributeMap.get("email"), "maduranga1@wso2.com");
//        Assert.assertEquals(attributeMap.get("firstname"), "Maduranga1");
//    }
//
//    @Test(priority = 9)
//    public void testUpdateUserAttributesPatch() throws IdentityStoreException {
//
////        List<Attribute> attributesToUpdate = new ArrayList();
////        Attribute attribute1 = new Attribute();
////        attribute1.setAttributeName("username");
////        attribute1.setAttributeValue("maduranga");
////        attributesToUpdate.add(attribute1);
////        Attribute attribute2 = new Attribute();
////        attribute2.setAttributeName("email");
////        attribute2.setAttributeValue("maduranga@wso2.com");
////        attributesToUpdate.add(attribute2);
////        Attribute attribute3 = new Attribute();
////        attribute3.setAttributeName("lastname");
////        attribute3.setAttributeValue("Siriwardena1");
////        attributesToUpdate.add(attribute3);
////
////        List<Attribute> attributesToDelete = new ArrayList();
////        Attribute attribute5 = new Attribute();
////        attribute5.setAttributeName("firstname");
////        attribute5.setAttributeValue("Maduranga1");
////        attributesToDelete.add(attribute5);
////
////        identityStoreConnector.updateUserAttributes("maduranga1", attributesToUpdate, attributesToDelete);
//
//        List<Attribute> attributesRetrieved = identityStoreConnector.getUserAttributeValues("maduranga");
//
//        Map<String, String> attributeMap = new HashMap<>();
//        for (Attribute attribute : attributesRetrieved) {
//            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
//        }
//        Assert.assertEquals(attributesRetrieved.size(), 3);
//        Assert.assertEquals(attributeMap.get("username"), "maduranga");
//        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
//        Assert.assertEquals(attributeMap.get("lastname"), "Siriwardena1");
//    }
//
////    @Test(priority = 10)
////    public void testDeleteUser() throws UserNotFoundException, IdentityStoreException {
////
////        identityStoreConnector.deleteUser("maduranga");
////        List<Attribute> userAttributeValues = identityStoreConnector.getUserAttributeValues("maduranga");
////
////        Assert.assertEquals(userAttributeValues.size(), 0);
////    }
//
//    @Test(priority = 11)
//    public void testUpdateGroupAttributesPut() throws IdentityStoreException {
//
////        List<Attribute> attributesToUpdate = new ArrayList();
////        Attribute attribute1 = new Attribute();
////        attribute1.setAttributeName("groupname");
////        attribute1.setAttributeValue("engineering1");
////        attributesToUpdate.add(attribute1);
////        Attribute attribute2 = new Attribute();
////        attribute2.setAttributeName("email");
////        attribute2.setAttributeValue("engineering1@wso2.com");
////        attributesToUpdate.add(attribute2);
////        Attribute attribute3 = new Attribute();
////        attribute3.setAttributeName("reportsto");
////        attribute3.setAttributeValue("director1@wso2.com");
////        attributesToUpdate.add(attribute3);
////
////        identityStoreConnector.updateGroupAttributes("engineering", attributesToUpdate);
//
//        List<Attribute> attributesRetrieved = identityStoreConnector.getGroupAttributeValues("engineering1");
//
//        Assert.assertEquals(attributesRetrieved.size(), 3);
//
//        Map<String, String> attributeMap = new HashMap<>();
//        for (Attribute attribute : attributesRetrieved) {
//            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
//        }
//        Assert.assertEquals(attributeMap.get("groupname"), "engineering1");
//        Assert.assertEquals(attributeMap.get("email"), "engineering1@wso2.com");
//        Assert.assertEquals(attributeMap.get("reportsto"), "director1@wso2.com");
//    }
//
////    @Test(priority = 12)
////    public void testUpdateGroupAttributesPatch() throws IdentityStoreException {
////
////        String now = LocalDateTime.now().toString();
////
////        List<Attribute> attributesToUpdate = new ArrayList();
////        Attribute attribute1 = new Attribute();
////        attribute1.setAttributeName("groupname");
////        attribute1.setAttributeValue("engineering");
////        attributesToUpdate.add(attribute1);
////        Attribute attribute2 = new Attribute();
////        attribute2.setAttributeName("email");
////        attribute2.setAttributeValue("engineering@wso2.com");
////        attributesToUpdate.add(attribute2);
////        Attribute attribute3 = new Attribute();
////        attribute3.setAttributeName("createdon");
////        attribute3.setAttributeValue(now);
////        attributesToUpdate.add(attribute3);
////
////        List<Attribute> attributesToDelete = new ArrayList();
////        Attribute attribute5 = new Attribute();
////        attribute5.setAttributeName("reportsto");
////        attribute5.setAttributeValue("director1@wso2.com");
////        attributesToDelete.add(attribute5);
////
////        identityStoreConnector.updateGroupAttributes("engineering1", attributesToUpdate, attributesToDelete);
////
////        List<Attribute> attributesRetrieved = identityStoreConnector.getGroupAttributeValues("engineering");
////
////        Map<String, String> attributeMap = new HashMap<>();
////        for (Attribute attribute : attributesRetrieved) {
////            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
////        }
////        Assert.assertEquals(attributeMap.get("groupname"), "engineering");
////        Assert.assertEquals(attributeMap.get("email"), "engineering@wso2.com");
////        Assert.assertEquals(attributeMap.get("createdon"), now);
////    }
//
//    //TODO change the expectedExceptions to GroupNotFoundException
////    @Test(priority = 13, expectedExceptions = {Exception.class}, expectedExceptionsMessageRegExp = "Group not found.*")
////    public void testDeleteGroup() throws IdentityStoreException, GroupNotFoundException {
////
////        identityStoreConnector.deleteGroup("engineering");
////        identityStoreConnector.getGroupBuilder("groupname", "engineering");
////    }
}


