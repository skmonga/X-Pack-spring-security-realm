package org.elasticsearch.springsecurity.realm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.user.User;

import com.google.gson.Gson;

public class SecureRealm extends Realm {

	public static final String TYPE = "spring-security";

	public static final String USER_HEADER = "User";

	public static final String AUTH_HEADER = "Authorization";

	/**
	 * This endpoint will be called for authentication + authorization
	 * This will fetch the roles associated with this user in elasticsearch
	 */
	private static final String ROLES_FETCH_ENDPOINT = "http://localhost:8080/greeting";

	public SecureRealm(RealmConfig config) {
		super(TYPE, config);
	}

	protected SecureRealm(String type, RealmConfig config) {
		super(TYPE, config);
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof OAuthToken;
	}

	@Override
	public OAuthToken token(ThreadContext threadContext) {
		String user = threadContext.getHeader(USER_HEADER);
		if (user != null) {
			String authHeader = threadContext.getHeader(AUTH_HEADER);
			if (authHeader != null) {
				return new OAuthToken(user, authHeader);
			}
		}
		return null;
	}

	/* 
	 * In OAuthToken param contains user and accessToken
	 * The user is used for fetching the roles associated with this 
	 * thirdparty authenticated user in Elasticsearch
	 */
	@Override
	public User authenticate(AuthenticationToken authenticationToken) {
		OAuthToken token = (OAuthToken) authenticationToken;
		final String actualUser = token.principal();
		String[] roles = null;
		try {
			roles = getESRolesForUser(token);
		} catch (IOException e) {
			logger.error("Error in authentication",e.getMessage());
		}
		if (roles != null)
			return new User(actualUser, roles);
		return null;
	}

	@Override
	public User lookupUser(String user) {
		return null;
	}

	@Override
	public boolean userLookupSupported() {
		return false;
	}
	
	private static String[] getESRolesForUser(OAuthToken token) throws IOException {
		HttpClient client = new DefaultHttpClient();
		HttpGet request = new HttpGet(ROLES_FETCH_ENDPOINT);
		request.addHeader(AUTH_HEADER,token.credentials());
		HttpResponse response = client.execute(request);
		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

		StringBuilder content = new StringBuilder();
		String line = "";
		while ((line = rd.readLine()) != null) {
			content.append(line);
		}
		Map<String,Object> responseMap = new Gson().fromJson(content.toString(), Map.class);
		if(responseMap != null) {
			String allRoles = (String) responseMap.get("content");
			if(allRoles != null)
				return allRoles.split(",");
		}
		return null;
	}
	
	/*public static void main(String[] args) throws IOException {
		String access_token = "871de7ae-ac51-4df0-bb25-bb67cf9326b9";
		String[] roles = getESRolesForUser(new OAuthToken("user", "Bearer " + access_token));
		for(String role : roles)
			System.out.println(role);
	}*/

}
