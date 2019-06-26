package com.study.usermnagement.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.study.usermnagement.model.Role;
import com.study.usermnagement.model.RoleName;

public interface RoleRepository extends JpaRepository<Role, Long> {

	Optional<Role> findByName(RoleName roleName);
}
