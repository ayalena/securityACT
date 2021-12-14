package com.example.securityACT.security;

public enum ApplicationUserPermission {
    CUSTOMER_READ("customer:read"),
    CUSTOMER_WRITE("customer:write"),
    PRODUCT_READ("product:read"),
    PRODUCT_WRITE("product:write");

    //define
    private final String permission;

    //assign to constructor
    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    //getter
    public String getPermission() {
        return permission;
    }


}
