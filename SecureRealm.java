package org.elasticsearch.springsecurity.realm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.user.User;

import com.google.gson.Gson;

/**
 * This realm allows login to client application via third party
 * authentication. Third party app is Spring Security with OAuth
 *
 */
public class SecureRealm  extends Realm {

	public static final String TYPE = "springsecurity";

	public static final String USER_HEADER = "User";

	public static final String AUTH_HEADER = "Authorization";

	/**
	 * This endpoint will be called for authentication + authorization This will
	 * fetch the roles associated with this user in elasticsearch
	 */
	private static final String ROLES_FETCH_ENDPOINT = "http://localhost:8080/fetch/roles";

	private static final String TOKEN_GEN_ENDPOINT = "http://localhost:8080/oauth/token";

	private static final String ACCESS_TOKEN_PREFIX = "Bearer ";
	
	private static final String ACCESS_TOKEN = "access_token";
	
	
	/**
	 * TODO :: Currently for every request, either token is present or it is generated for the user. 
	 * Advancement is the below placeholder for user and their info (accessToken and esroles) but need 
	 * a proper cache with LRU and eviction mechanism.
	 */
	private final ConcurrentMap<String, InfoHolder> userInfo = new ConcurrentHashMap<String,InfoHolder>();

	/**
	 * The placeholder for testing purposes. Will hold username as key and
	 * complete AppUser as value where Appuser has all fields needed to generate
	 * access token
	 */
	private static Map<String, AppUser> userMap = new HashMap<String, AppUser>();

	// place all users for testing in userMap
	static {
		userMap.put("roy", new AppUser("roy", "spring", "password",
				"read write", "clientapp", "123456"));
		userMap.put("all_access", new AppUser("all_access", "spring", "password",
				"read write", "clientapp", "123456"));
		userMap.put("read_access", new AppUser("read_access", "spring", "password",
				"read write", "clientapp", "123456"));
		userMap.put("payments_access", new AppUser("payments_access", "spring", "password",
				"read write", "clientapp", "123456"));
	}

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
			} else {
				//check if token for user present in the map userTokens
				// if not,generate token for this user and put into the map
				try {
					authHeader = generateAccessToken(user);
					logger.info("Token generated for user {} : {}",user,authHeader);
					return new OAuthToken(user, ACCESS_TOKEN_PREFIX + authHeader);
				} catch (IOException e) {
					//add logger
					logger.error("Error while generating access token for user : " + user, e.getMessage());
				}
			}
		}
		return null;
	}

	/*
	 * In OAuthToken param contains user and accessToken The user is used for
	 * fetching the roles associated with this thirdparty authenticated user in
	 * Elasticsearch
	 */
	@Override
	public User authenticate(AuthenticationToken authenticationToken) {
		OAuthToken token = (OAuthToken) authenticationToken;
		final String actualUser = token.principal();
		String[] roles = null;
		try {
			roles = getESRolesForUser(token);
		} catch (IOException e) {
			logger.error("Error in authentication", e.getMessage());
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

	private String[] getESRolesForUser(OAuthToken token) throws IOException {
		HttpClient client = new DefaultHttpClient();
		HttpGet request = new HttpGet(ROLES_FETCH_ENDPOINT);
		request.addHeader(AUTH_HEADER, token.credentials());
		HttpResponse response = client.execute(request);
		BufferedReader rd = new BufferedReader(new InputStreamReader(response
				.getEntity().getContent()));

		StringBuilder content = new StringBuilder();
		String line = "";
		while ((line = rd.readLine()) != null) {
			content.append(line);
		}

		SecurityManager sm = System.getSecurityManager();
		if (sm != null) {
			sm.checkPermission(new SpecialPermission());
		}
		Map<String, Object> responseMap = AccessController
				.doPrivileged((PrivilegedAction<Map<String, Object>>) () -> {
					return new Gson().fromJson(content.toString(), Map.class);
				});
		
		if(responseMap.containsKey("roles")) {
			String allRoles = (String) responseMap.get("roles");
			if (allRoles != null)
				return allRoles.split(",");
		}
		
		return null;
	}
	
	private String generateAccessToken(String user) throws IOException {
		AppUser appUser = userMap.get(user);
		if (appUser != null) {
			// include prefix for token as well
			HttpClient client = new DefaultHttpClient();
			HttpPost request = new HttpPost(TOKEN_GEN_ENDPOINT);
			request.addHeader("Content-Type",
					"application/x-www-form-urlencoded");
			request.addHeader(
					AUTH_HEADER,
					"Basic "
							+ Base64.encodeBase64String((appUser.getClientId()
									+ ":" + appUser.getClientSecret())
									.getBytes()));
			

			List<NameValuePair> params = new ArrayList<NameValuePair>();
			params.add(new BasicNameValuePair("password",appUser.getPassword()));
			params.add(new BasicNameValuePair("username",appUser.getUserName()));
			params.add(new BasicNameValuePair("grant_type",appUser.getGrantType()));
			params.add(new BasicNameValuePair("scope",appUser.getScope()));
			params.add(new BasicNameValuePair("client_secret",appUser.getClientSecret()));
			params.add(new BasicNameValuePair("client_id",appUser.getClientId()));
			
			UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params,"UTF-8");
			request.setEntity(entity);
			HttpResponse response = client.execute(request);
			BufferedReader rd = new BufferedReader(new InputStreamReader(response
					.getEntity().getContent()));

			StringBuilder content = new StringBuilder();
			String line = "";
			while ((line = rd.readLine()) != null) {
				content.append(line);
			}
			
			SecurityManager sm = System.getSecurityManager();
			if (sm != null) {
				sm.checkPermission(new SpecialPermission());
			}
			Map<String, Object> responseMap = AccessController.doPrivileged((PrivilegedAction<Map<String, Object>>) () -> { 
					return new Gson().fromJson(content.toString(), Map.class);
			});
			
			if(responseMap != null && responseMap.containsKey(ACCESS_TOKEN))
				return (String) responseMap.get(ACCESS_TOKEN);
		}
		return null;
	}
	
	private static class InfoHolder {
		private String accessToken;
		private String[] esRoles;
		
	
		public InfoHolder(String token, String[] roles) {
			this.accessToken = token;
			this.esRoles = roles;
		}
	}

}
