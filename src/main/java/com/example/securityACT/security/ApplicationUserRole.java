package com.example.securityACT.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.securityACT.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    CUSTOMER(Sets.newHashSet()), //empty bc no permissions
    ADMIN(Sets.newHashSet(PRODUCT_READ, PRODUCT_WRITE, CUSTOMER_READ, CUSTOMER_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(PRODUCT_READ, CUSTOMER_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
