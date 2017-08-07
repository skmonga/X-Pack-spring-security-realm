package org.elasticsearch.springsecurity.realm;

import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;

public class SecureRealmFactory implements Realm.Factory{

	@Override
	public Realm create(RealmConfig config) throws Exception {
		return new SecureRealm(config);
	}

}
