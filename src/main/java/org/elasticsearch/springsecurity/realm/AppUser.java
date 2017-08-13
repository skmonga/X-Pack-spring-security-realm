package org.elasticsearch.springsecurity.realm;

public class AppUser {

	private String userName;
	private String password;
	private String grantType;
	private String scope;
	private String clientId;
	private String clientSecret;
	
	public AppUser(String userName, String password, String grantType, String scope, String clientId,
			String clientSecret) {
		super();
		this.userName = userName;
		this.password = password;
		this.grantType = grantType;
		this.scope = scope;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getGrantType() {
		return grantType;
	}

	public void setGrantType(String grantType) {
		this.grantType = grantType;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
}
