/*
 * Tigase XMPP Server - The instant messaging server
 * Copyright (C) 2004 Tigase, Inc. (office@tigase.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. Look for COPYING file in the top folder.
 * If not, see http://www.gnu.org/licenses/.
 */
package demo.sasl.did;

import demo.sasl.did.client.DidSaslClientFactory;
import demo.sasl.did.server.DidSaslServerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.Provider;

public final class DidSaslProvider extends Provider {

	public static final String MECHANISM_NAME = "DID-CHALLENGE";

	private static final String PROVIDER_NAME = "demo.sasl.did";
	private static final String PROVIDER_VERSION = "1.0";
	private static final String PROVIDER_INFO = "A SASL provider for a DID-based authentication mechanism";

	private static final Logger log = LogManager.getLogger(DidSaslProvider.class);

	public DidSaslProvider() {
		super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
		this.put("SaslClientFactory." + MECHANISM_NAME, DidSaslClientFactory.class.getName());
		this.put("SaslServerFactory." + MECHANISM_NAME, DidSaslServerFactory.class.getName());
	}

	@Override
	protected synchronized void putService(Service s) {
		log.info("Putting SASL service '{}' with class '{}'", s.getAlgorithm(), s.getClassName());
		super.putService(s);
	}

	@Override
	protected synchronized void removeService(Service s) {
		log.info("Removing SASL service '{}' with class '{}'", s.getAlgorithm(), s.getClassName());
		super.removeService(s);
	}
}
