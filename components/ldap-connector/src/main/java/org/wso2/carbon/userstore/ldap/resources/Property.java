package org.wso2.carbon.userstore.ldap.resources;

import java.util.Arrays;

public class Property {
    private String name;
    private String value;
    private String description;
    private Property[] childProperties;

    public Property(String name, String value, String description, Property[] childProperties) {
        this.name = name;
        this.value = value;
        this.description = description;
        if (childProperties == null) {
            this.childProperties = new Property[0];
        } else {
            this.childProperties = Arrays.copyOf(childProperties, childProperties.length);
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Property[] getChildProperties() {
        return childProperties;
    }

    public void setChildProperties(Property[] childProperties) {
        if (childProperties == null) {
            this.childProperties = new Property[0];
        } else {
            this.childProperties = Arrays.copyOf(childProperties, childProperties.length);
        }
    }
}