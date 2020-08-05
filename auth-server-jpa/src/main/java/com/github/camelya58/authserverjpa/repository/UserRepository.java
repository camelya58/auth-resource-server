package com.github.camelya58.authserverjpa.repository;

import com.github.camelya58.authserverjpa.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

/**
 * Interface UserRepository connects with PostgreSQL database.
 *
 * @author Kamila Meshcheryakova
 * created 04.08.2020
 */
@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {

    User findUserByUsername(String username);
}
