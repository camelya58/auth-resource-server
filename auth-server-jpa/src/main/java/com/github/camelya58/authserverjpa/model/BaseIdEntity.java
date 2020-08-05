package com.github.camelya58.authserverjpa.model;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

/**
 * Class BaseIdEntity is a super class for entities.
 *
 * @author Kamila Meshcheryakova
 * created 04.08.2020
 */
@MappedSuperclass
public class BaseIdEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected long id;
}
