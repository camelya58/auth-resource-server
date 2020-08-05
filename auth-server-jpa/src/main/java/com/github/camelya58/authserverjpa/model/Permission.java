package com.github.camelya58.authserverjpa.model;

import javax.persistence.Entity;

/**
 * Class Permission contains a field describing authorities.
 *
 * @author Kamila Meshcheryakova
 * created 04.08.2020
 */
@Entity(name = "permission")
public class Permission extends BaseIdEntity {
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
