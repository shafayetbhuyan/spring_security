package com.springsecurity.spr_security.entiry;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;
    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String userName;
    @Column(nullable = false)
    private String password;
    private int active;
    private String roles = "";
    private String permissions = "";

    protected User() {
    }

    public User(String name, String userName, String password, String roles, String permissions) {
        this.name = name;
        this.userName = userName;
        this.password = password;
        this.active = 1;
        this.roles = roles;
        this.permissions = permissions;
    }

    public long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public int getActive() {
        return active;
    }

    public String getRoles() {
        return roles;
    }

    public String getPermissions() {
        return permissions;
    }

    public List<String> getRolesList(){
        if (this.roles.length() >0 ){
            return Arrays.asList(roles.split(","));
        }
        return new ArrayList<>();
    }

    public List<String> getPermissionsList(){
        if (this.permissions.length() >0 ){
            return Arrays.asList(permissions.split(","));
        }
        return new ArrayList<>();
    }

}
