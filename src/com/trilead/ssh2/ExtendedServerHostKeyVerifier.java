package com.trilead.ssh2;

import java.util.List;

/**
 * This extends the {@link ServerHostKeyVerifier} interface by allowing the remote server to indicate it has multiple
 * server key algorithms available. After authentication, the {@link #getKnownKeyAlgorithmsForHost(String, int)} method
 * may be called and compared against the list of server-controller keys. If a key algorithm has been added then
 * {@link #addServerHostKey(String, int, String, byte[])} will be called. If a key algorithm has been removed, then
 * {@link #removeServerHostKey(String, int, String, byte[])} will be called.
 *
 * @author Kenny Root
 */
public abstract class ExtendedServerHostKeyVerifier implements ServerHostKeyVerifier {
	/**
	 * Called during connection to determine which keys are known for this host.
	 *
	 * @param hostname the hostname used to create the {@link Connection} object
	 * @param port the server's remote TCP port
	 * @return list of hostkey algorithms for the given <code>hostname</code> and <code>port</code> combination
	 * 			or {@code null} if none are known.
	 */
	public abstract List<String> getKnownKeyAlgorithmsForHost(String hostname, int port);

	/**
	 * After authentication, if the server indicates it no longer uses this key, this method will be called
	 * for the app to remove its record of it.
	 *
	 * @param hostname the hostname used to create the {@link Connection} object
	 * @param port the server's remote TCP port
	 * @param serverHostKeyAlgorithm key algorithm of removed key
	 * @param serverHostKey key data of removed key
	 */
	public abstract void removeServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
			byte[] serverHostKey);

	/**
	 * After authentication, if the server indicates it has another <code>keyAlgorithm</code>, this method will be
	 * called for the app to add it to its record of known keys for this <code>hostname</code>.
	 *
	 * @param hostname the hostname used to create the {@link Connection} object
	 * @param port the server's remote TCP port
	 * @param keyAlgorithm SSH standard name for the key to be added
	 * @param serverHostKey SSH encoding of the key data for the key to be added
	 */
	public abstract void addServerHostKey(String hostname, int port, String keyAlgorithm, byte[] serverHostKey);
}
