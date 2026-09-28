package com.trilead.ssh2;

import com.trilead.ssh2.crypto.dh.Sntrup761X25519Exchange;
import org.junit.Test;

/**
 * Unit tests for configuring key exchange preferences on {@link Connection}.
 */
public class ConnectionKexAlgorithmTest {

	@Test
	public void setKexAlgorithmsAcceptsSntrupNamesForExplicitInteropTesting() {
		Connection connection = new Connection("localhost");

		connection.setKexAlgorithms(new String[] {
				Sntrup761X25519Exchange.NAME,
				Sntrup761X25519Exchange.ALT_NAME
		});
	}

	@Test(expected = IllegalArgumentException.class)
	public void setKexAlgorithmsRejectsUnknownNames() {
		new Connection("localhost").setKexAlgorithms(new String[] { "sntrup761x25519-sha512@example.com" });
	}
}
