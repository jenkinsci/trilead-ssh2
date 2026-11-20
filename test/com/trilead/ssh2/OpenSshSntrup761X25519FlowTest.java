package com.trilead.ssh2;

import com.trilead.ssh2.crypto.dh.Sntrup761X25519Exchange;
import org.junit.Assume;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

/**
 * Optional end-to-end OpenSSH verification for SNTRUP761/X25519 negotiation.
 *
 * <p>This test is skipped unless {@code TRILEAD_OPENSSH_SNTRUP_HOST} is set. The target server
 * must be configured to offer {@code sntrup761x25519-sha512@openssh.com}, ideally as the only
 * {@code KexAlgorithms} entry so the flow is deterministic.</p>
 */
public class OpenSshSntrup761X25519FlowTest {

	private static final String HOST = "TRILEAD_OPENSSH_SNTRUP_HOST";
	private static final String PORT = "TRILEAD_OPENSSH_SNTRUP_PORT";
	private static final int DEFAULT_SSH_PORT = 22;

	@Test
	public void negotiatesSntrupAgainstOpenSsh() throws IOException {
		String host = System.getenv(HOST);
		Assume.assumeTrue("Set " + HOST + " to run the OpenSSH SNTRUP761/X25519 flow test", host != null && !host.isEmpty());

		Connection connection = new Connection(host, getPort());
		connection.setKexAlgorithms(new String[] { Sntrup761X25519Exchange.ALT_NAME });

		try {
			ConnectionInfo info = connection.connect(new ServerHostKeyVerifier() {
				@Override
				public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) {
					return true;
				}
			}, 0, 0);
			assertEquals(Sntrup761X25519Exchange.ALT_NAME, info.keyExchangeAlgorithm);
		} finally {
			connection.close();
		}
	}

	private static int getPort() {
		String value = System.getenv(PORT);
		if (value == null || value.isEmpty()) {
			return DEFAULT_SSH_PORT;
		}
		return Integer.parseInt(value);
	}
}
