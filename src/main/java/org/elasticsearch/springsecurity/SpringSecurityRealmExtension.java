package org.elasticsearch.springsecurity;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.example.realm.CustomAuthenticationFailureHandler;
import org.elasticsearch.springsecurity.realm.SecureRealm;
import org.elasticsearch.springsecurity.realm.SecureRealmFactory;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.extensions.XPackExtension;
import org.elasticsearch.xpack.security.authc.AuthenticationFailureHandler;
import org.elasticsearch.xpack.security.authc.Realm.Factory;

public class SpringSecurityRealmExtension extends XPackExtension {

	@Override
	public String name() {
		return "spring-security-extension";
	}

	@Override
	public String description() {
		return "a spring-security based third party authentication and authorization plugin";
	}

	/**
	 * Returns a collection of header names that will be used by this extension.
	 * This is necessary to ensure the headers are copied from the incoming
	 * request and made available to your realm(s).
	 */
	@Override
	public Collection<String> getRestHeaders() {
		return Arrays.asList(SecureRealm.USER_HEADER, SecureRealm.ACCESS_TOKEN_HEADER);
	}

	/**
	 * Returns a map of the custom realms provided by this extension. The first
	 * parameter is the string representation of the realm type; this is the
	 * value that is specified when declaring a realm in the settings. Note, the
	 * realm type cannot be one of the types defined by X-Pack. In order to
	 * avoid a conflict, you may wish to use some prefix to your realm types.
	 *
	 * The second parameter is an instance of the {@link Factory}
	 * implementation. This factory class will be used to create realms of this
	 * type that are defined in the elasticsearch settings.
	 */
	@Override
	public Map<String, Factory> getRealms(ResourceWatcherService resourceWatcherService) {
		return new MapBuilder<String, Factory>().put(SecureRealm.TYPE, new SecureRealmFactory())
				.immutableMap();
	}

	/**
	 * Returns the custom authentication failure handler. Note only one
	 * implementation and instance of a failure handler can exist. There is a
	 * default implementation,
	 * {@link org.elasticsearch.xpack.security.authc.DefaultAuthenticationFailureHandler}
	 * that can be extended where appropriate. If no changes are needed to the
	 * default implementation, then there is no need to override this method.
	 */
	@Override
	public AuthenticationFailureHandler getAuthenticationFailureHandler() {
		return new CustomAuthenticationFailureHandler();
	}

}
