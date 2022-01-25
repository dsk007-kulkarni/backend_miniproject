package com.miniproject.miniproject_jwt_auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.miniproject.miniproject_jwt_auth.models.ERole;
import com.miniproject.miniproject_jwt_auth.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}