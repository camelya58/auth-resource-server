package com.github.camelya58.authserverjpa.model;

import javax.persistence.*;
import java.util.List;

/**
 * Class Role contains the list of user authorities.
 *
 * @author Kamila Meshcheryakova
 * created 04.08.2020
 */
@Entity(name = "role")
public class Role extends BaseIdEntity {

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "permission_role", joinColumns = {
            @JoinColumn(name = "role_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "permission_id", referencedColumnName = "id")})
    private List<Permission> permissions;

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Permission> permissions) {
        this.permissions = permissions;
    }
}
