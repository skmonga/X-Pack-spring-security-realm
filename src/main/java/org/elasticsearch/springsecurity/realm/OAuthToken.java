package org.elasticsearch.springsecurity.realm;

import org.elasticsearch.xpack.security.authc.AuthenticationToken;

public class OAuthToken implements AuthenticationToken {

	private String user;
	
	private String accessToken;
	
	public OAuthToken(String user, String token) {
		this.user = user;
		this.accessToken = token;
	}

	@Override
	public String principal() {
		return user;
	}
	
	@Override
	public String credentials() {
		return accessToken;
	}
	
	@Override
	public void clearCredentials() {
		accessToken = null;
	}
	
}
