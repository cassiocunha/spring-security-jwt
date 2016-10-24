package com.monkeyhand.security.factory;

import com.monkeyhand.security.domain.entity.AppUser;
import com.monkeyhand.security.model.SpringSecurityUser;

public class SpringSecurityUserFactory {

	public static SpringSecurityUser create(AppUser user) {
		return new SpringSecurityUser(user.getUserId(), user.getUsername(), user.getPassword(), user.getPassword(), user.getLastPasswordReset(), user.getRoles());
	}
}
