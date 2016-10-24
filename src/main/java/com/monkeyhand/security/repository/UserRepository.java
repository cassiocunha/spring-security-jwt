package com.monkeyhand.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.monkeyhand.security.domain.entity.AppUser;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {
	
	@Query("select u from AppUser u where u.username = :username")
	public AppUser findByUserName(@Param(value = "username") String username);
}
