
package com.trilead.ssh2;

import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.digest.Digest;
import com.trilead.ssh2.crypto.digest.MD5;
import com.trilead.ssh2.crypto.digest.MessageMac;
import com.trilead.ssh2.crypto.digest.SHA1;
import com.trilead.ssh2.log.Logger;

import com.trilead.ssh2.signature.KeyAlgorithm;
import com.trilead.ssh2.signature.KeyAlgorithmManager;


/**
 * The KnownHosts class is a handy tool to verify received server hostkeys
 * based on the information in <code>known_hosts</code> files (the ones used by OpenSSH).
 * <p>
 * It offers basically an in-memory database for known_hosts entries, as well as some
 * helper functions. Entries from a <code>known_hosts</code> file can be loaded at construction time.
 * It is also possible to add more keys later (e.g., one can parse different
 * known_hosts files).
 *
 * <p>
 * It is a thread safe implementation, therefore, you need only to instantiate one
 * KnownHosts for your whole application.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: KnownHosts.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */

public class KnownHosts
{
	private static final Logger LOGGER = Logger.getLogger(KnownHosts.class);

	public static final int HOSTKEY_IS_OK = 0;
	public static final int HOSTKEY_IS_NEW = 1;
	public static final int HOSTKEY_HAS_CHANGED = 2;
    private static final SecureRandom SECURE_RANDOM = RandomFactory.create();

	private class KnownHostsEntry
	{
		private final String[] patterns;
		private final PublicKey key;
		private final String algorithm;

		private KnownHostsEntry(String[] patterns, PublicKey key, String algorithm)
		{
			this.patterns = patterns;
			this.key = key;
			this.algorithm = algorithm;
		}
	}

	private final LinkedList<KnownHostsEntry> publicKeys = new LinkedList<>();

	public KnownHosts()
	{
	}

	public KnownHosts(char[] knownHostsData) throws IOException
	{
		initialize(knownHostsData);
	}

	public KnownHosts(File knownHosts) throws IOException
	{
		initialize(knownHosts);
	}

	/**
	 * Adds a single public key entry to the database. Note: this will NOT add the public key
	 * to any physical file (e.g., "~/.ssh/known_hosts") - use <code>addHostkeyToFile()</code> for that purpose.
	 * This method is designed to be used in a {@link ServerHostKeyVerifier}.
	 * 
	 * @param hostnames a list of hostname patterns - at least one most be specified. Check out the
	 *        OpenSSH sshd man page for a description of the pattern matching algorithm.
	 * @param serverHostKeyAlgorithm as passed to the {@link ServerHostKeyVerifier}.
	 * @param serverHostKey as passed to the {@link ServerHostKeyVerifier}.
	 * @throws IOException on failure trying to convert the host key to a saveable format
	 */
	public void addHostkey(String[] hostnames, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException {
		if (hostnames == null) {
			throw new IllegalArgumentException("hostnames may not be null");
		}

		for (KeyAlgorithm<PublicKey, PrivateKey> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
			if (serverHostKeyAlgorithm.equals(algorithm.getKeyFormat())) {
				PublicKey publicKey = algorithm.decodePublicKey(serverHostKey);
				synchronized (publicKeys) {
					publicKeys.add(new KnownHostsEntry(hostnames, publicKey, serverHostKeyAlgorithm));
				}
				return;
			}
		}

		throw new IOWarningException("Unknwon host key type (" + serverHostKeyAlgorithm + ")");
	}

	/**
	 * Parses the given known_hosts data and adds entries to the database.
	 * 
	 * @param knownHostsData the known hosts data to parse
	 * @throws IOException on failure reading the parsing the known hosts data
	 */
	public void addHostkeys(char[] knownHostsData) throws IOException
	{
		initialize(knownHostsData);
	}

	/**
	 * Parses the given known_hosts file and adds entries to the database.
	 * 
	 * @param knownHosts the file to read the existing known hosts entries feom, add to add any new entries to
	 * @throws IOException on failure reading the existing known hosts file
	 */
	public void addHostkeys(File knownHosts) throws IOException
	{
		initialize(knownHosts);
	}

	/**
	 * Generate the hashed representation of the given hostname. Useful for adding entries
	 * with hashed hostnames to a known_hosts file. (see -H option of OpenSSH key-gen).
	 *  
	 * @param hostname the hostname to hash
	 * @return the hashed representation, e.g., "|1|cDhrv7zwEUV3k71CEPHnhHZezhA=|Xo+2y6rUXo2OIWRAYhBOIijbJMA="
	 */
	public static String createHashedHostname(String hostname)
	{
		SHA1 sha1 = new SHA1();

		byte[] salt = new byte[sha1.getDigestLength()];

		SECURE_RANDOM.nextBytes(salt);

		byte[] hash = hmacSha1Hash(salt, hostname);

		String base64_salt = new String(Base64.encode(salt));
		String base64_hash = new String(Base64.encode(hash));

		return "|1|" + base64_salt + "|" + base64_hash;
	}

	private static byte[] hmacSha1Hash(byte[] salt, String hostname)
	{

		if (salt.length != 20) {
			throw new IllegalArgumentException("Salt has wrong length (" + salt.length + ")");
		}

		MessageMac messageMac = new MessageMac("hmac-sha1", salt);

		try {
			byte[] message = hostname.getBytes("ISO-8859-1");
			messageMac.update(message, 0, message.length);
		} catch (UnsupportedEncodingException ignore) {
		/* Actually, ISO-8859-1 is supported by all correct
		 * Java implementations. But... you never know. */
			byte[] message = hostname.getBytes();
			messageMac.update(message, 0, message.length);
		}

		byte[] dig = new byte[20];

		messageMac.getMac(dig, 0);

		return dig;
	}

	private boolean checkHashed(String entry, String hostname)
	{
		if (!entry.startsWith("|1|"))
			return false;

		int delim_idx = entry.indexOf('|', 3);

		if (delim_idx == -1)
			return false;

		String salt_base64 = entry.substring(3, delim_idx);
		String hash_base64 = entry.substring(delim_idx + 1);

		byte[] salt = null;
		byte[] hash = null;

		try
		{
			salt = Base64.decode(salt_base64.toCharArray());
			hash = Base64.decode(hash_base64.toCharArray());
		}
		catch (IOException e)
		{
			return false;
		}

		SHA1 sha1 = new SHA1();

		if (salt.length != sha1.getDigestLength())
			return false;

		byte[] dig = hmacSha1Hash(salt, hostname);

		for (int i = 0; i < dig.length; i++)
			if (dig[i] != hash[i])
				return false;

		return true;
	}

	private int checkKey(String remoteHostname, PublicKey remoteKey)
	{
		int result = HOSTKEY_IS_NEW;

		synchronized (publicKeys)
		{

			for (KnownHostsEntry ke : publicKeys) {
				if (!hostnameMatches(ke.patterns, remoteHostname))
					continue;

				boolean res = matchKeys(ke.key, remoteKey);

				if (res)
					return HOSTKEY_IS_OK;

				result = HOSTKEY_HAS_CHANGED;
			}
		}
		return result;
	}

	private Vector<KnownHostsEntry> getAllKnownHostEntries(String hostname)
	{
		Vector<KnownHostsEntry> knownHostsEntries = new Vector<>();

		synchronized (publicKeys)
		{

			for (KnownHostsEntry ke : publicKeys) {
				if (hostnameMatches(ke.patterns, hostname)) {
					knownHostsEntries.addElement(ke);
				}
			}
		}

		return knownHostsEntries;
	}

	/**
	 * Try to find the preferred order of hostkey algorithms for the given hostname.
	 * Based on the type of hostkey that is present in the internal database.
	 * an ordered list of hostkey algorithms is returned which can be passed
	 * to <code>Connection.setServerHostKeyAlgorithms</code>. 
	 * 
	 * @param hostname the hostname (or hostname pattern) to search for
	 * @return <code>null</code> if no key for the given hostname is present or
	 * there are keys of multiple types present for the given hostname. Otherwise,
	 * an array with hostkey algorithms is returned.
	 */
	public String[] getPreferredServerHostkeyAlgorithmOrder(String hostname)
	{
		String[] algos = recommendHostkeyAlgorithms(hostname);

		if (algos != null)
			return algos;

		InetAddress[] ipAddresses;

		try
		{
			ipAddresses = InetAddress.getAllByName(hostname);
		}
		catch (UnknownHostException e)
		{
			return null;
		}

		for (InetAddress ipAddress : ipAddresses) {
			algos = recommendHostkeyAlgorithms(ipAddress.getHostAddress());

			if (algos != null)
				return algos;
		}

		return null;
	}

	private boolean hostnameMatches(String[] hostpatterns, String hostname)
	{
		boolean isMatch = false;
		boolean negate = false;

		hostname = hostname.toLowerCase();

		for (String hostpattern : hostpatterns) {
			if (hostpattern == null)
				continue;

			String pattern = null;

			/* In contrast to OpenSSH we also allow negated hash entries (as well as hashed
			 * entries in lines with multiple entries).
			 */

			if ((hostpattern.length() > 0) && (hostpattern.charAt(0) == '!')) {
				pattern = hostpattern.substring(1);
				negate = true;
			} else {
				pattern = hostpattern;
				negate = false;
			}

			/* Optimize, no need to check this entry */

			if (isMatch && !negate)
				continue;

			/* Now compare */

			if (pattern.charAt(0) == '|') {
				if (checkHashed(pattern, hostname)) {
					if (negate)
						return false;
					isMatch = true;
				}
			} else {
				pattern = pattern.toLowerCase();

				if ((pattern.indexOf('?') != -1) || (pattern.indexOf('*') != -1)) {
					if (pseudoRegex(pattern.toCharArray(), 0, hostname.toCharArray(), 0)) {
						if (negate)
							return false;
						isMatch = true;
					}
				} else if (pattern.compareTo(hostname) == 0) {
					if (negate)
						return false;
					isMatch = true;
				} else {
					final int indexColon = pattern.indexOf(':');
					final int indexLastColon = pattern.indexOf(':');
					if (indexColon > 0 && indexColon < pattern.length() - 2 && indexColon == indexLastColon) {
						final String bracketizedHost = '[' + hostname + ']';
						if (pattern.startsWith(bracketizedHost)) {
							if (negate)
								return false;
							isMatch = true;
						}
					}
				}
			}
		}

		return isMatch;
	}

	private void initialize(char[] knownHostsData) throws IOException {
		final BufferedReader br = new BufferedReader(new CharArrayReader(knownHostsData));
		for (String line = br.readLine(); line != null; line = br.readLine()) {
			line = line.trim();
			if (line.startsWith("#")) {
				continue;
			}

			final String[] arr = line.split(" "); 
			if (arr.length < 3) {
				continue;
			}

			final String serverHostKeyAlgorithm = arr[1];

			boolean supportedKeyType = false;

			for (KeyAlgorithm<PublicKey, PrivateKey> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
				if (algorithm.getKeyFormat().equals(serverHostKeyAlgorithm)) {
					supportedKeyType = true;
					break;
				}
			}

			if (!supportedKeyType) {
				LOGGER.log(1, "Unsupported key type: " + serverHostKeyAlgorithm);
				continue;
			}

			final String[] hostnames = arr[0].split(",");
			final byte[] msg = Base64.decode(arr[2].toCharArray());

			try {
				addHostkey(hostnames, serverHostKeyAlgorithm, msg);
			}
			catch (IOWarningException ex) {
				LOGGER.log(30, "Ignored invalid line '" + line + "'",ex);
			}
		}
	}

	private void initialize(File knownHosts) throws IOException {
		final char[] buffer = new char[512];

		final CharArrayWriter charWriter = new CharArrayWriter();

		if (!knownHosts.createNewFile()) {
			LOGGER.log(10, "Could not create known hosts file");
		}

		try (Reader reader = new FileReader(knownHosts)) {
			while (true) {
				final int readCharCount = reader.read(buffer);
				if (readCharCount < 0) {
					break;
				}

				charWriter.write(buffer, 0, readCharCount);
			}
		}

		initialize(charWriter.toCharArray());
	}

	private boolean matchKeys(PublicKey key1, PublicKey key2)
	{
		if (null == key1) {
		    return null == key2;
        }
        return key1.equals(key2);
	}

	private boolean pseudoRegex(char[] pattern, int i, char[] match, int j)
	{
		/* This matching logic is equivalent to the one present in OpenSSH 4.1 */

		while (true)
		{
			/* Are we at the end of the pattern? */

			if (pattern.length == i)
				return (match.length == j);

			if (pattern[i] == '*')
			{
				i++;

				if (pattern.length == i)
					return true;

				if ((pattern[i] != '*') && (pattern[i] != '?'))
				{
					while (true)
					{
						if ((pattern[i] == match[j]) && pseudoRegex(pattern, i + 1, match, j + 1))
							return true;
						j++;
						if (match.length == j)
							return false;
					}
				}

				while (true)
				{
					if (pseudoRegex(pattern, i, match, j))
						return true;
					j++;
					if (match.length == j)
						return false;
				}
			}

			if (match.length == j)
				return false;

			if ((pattern[i] != '?') && (pattern[i] != match[j]))
				return false;

			i++;
			j++;
		}
	}

	private String[] recommendHostkeyAlgorithms(String hostname)
	{
		String preferredAlgo = null;

		Vector<KnownHostsEntry> keys = getAllKnownHostEntries(hostname);

		for (KnownHostsEntry key : keys) {
			String thisAlgo = key.algorithm;

			if (preferredAlgo != null) {
				/* If we find different key types, then return null */

				if (!preferredAlgo.equals(thisAlgo)) {
					return null;
				}

			} else {
				preferredAlgo = thisAlgo;
			}
		}

		/* If we did not find anything that we know of, return null */

		if (preferredAlgo == null)
			return null;

		/* Now put the preferred algo to the start of the array.
		 * You may ask yourself why we do it that way - basically, we could just
		 * return only the preferred algorithm: since we have a saved key of that
		 * type (sent earlier from the remote host), then that should work out.
		 * However, imagine that the server is (for whatever reasons) not offering
		 * that type of hostkey anymore (e.g., "algorithm-a" was disabled and
		 * now "algorithm-b" is being used). If we then do not let the server send us
		 * a fresh key of the new type, then we shoot ourself into the foot:
		 * the connection cannot be established and hence the user cannot decide
		 * if he/she wants to accept the new key.
		 */

		List<String> supportedAlgorithms = new ArrayList<>();

		for (KeyAlgorithm<?, ?> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
			supportedAlgorithms.add(supportedAlgorithms.size(), algorithm.getKeyFormat());
		}

		if (supportedAlgorithms.contains(preferredAlgo)) {
			supportedAlgorithms.remove(preferredAlgo);
			supportedAlgorithms.add(0, preferredAlgo);
		}
		return supportedAlgorithms.toArray(new String[supportedAlgorithms.size()]);

	}

	/**
	 * Checks the internal hostkey database for the given hostkey.
	 * If no matching key can be found, then the hostname is resolved to an IP address
	 * and the search is repeated using that IP address.
	 * 
	 * @param hostname the server's hostname, will be matched with all hostname patterns
	 * @param serverHostKeyAlgorithm type of hostkey being verified
	 * @param serverHostKey the key blob
	 * @return <ul>
	 *         <li><code>HOSTKEY_IS_OK</code>: the given hostkey matches an entry for the given hostname</li>
	 *         <li><code>HOSTKEY_IS_NEW</code>: no entries found for this hostname and this type of hostkey</li>
	 *         <li><code>HOSTKEY_HAS_CHANGED</code>: hostname is known, but with another key of the same type
	 *         (man-in-the-middle attack?)</li>
	 *         </ul>
	 * @throws IOException if the supplied key blob cannot be parsed or does not match the given hostkey type.
	 */
	public int verifyHostkey(String hostname, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException
	{
		PublicKey remoteKey = decodeHostKey(serverHostKeyAlgorithm, serverHostKey);

		int result = checkKey(hostname, remoteKey);

		if (result == HOSTKEY_IS_OK)
			return result;

		InetAddress[] ipAdresses;

		try
		{
			ipAdresses = InetAddress.getAllByName(hostname);
		}
		catch (UnknownHostException e)
		{
			return result;
		}

		for (InetAddress ipAdress : ipAdresses) {
			int newresult = checkKey(ipAdress.getHostAddress(), remoteKey);

			if (newresult == HOSTKEY_IS_OK)
				return newresult;

			if (newresult == HOSTKEY_HAS_CHANGED)
				result = HOSTKEY_HAS_CHANGED;
		}

		return result;
	}

	private PublicKey decodeHostKey(String hostKeyAlgorithm, byte[] encodedHostKey) throws IOException {
		for (KeyAlgorithm<PublicKey, PrivateKey> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
			if (algorithm.getKeyFormat().equals(hostKeyAlgorithm)) {
				return algorithm.decodePublicKey(encodedHostKey);
			}
		}

		throw new IllegalArgumentException("Unknown hostkey type " + hostKeyAlgorithm);
	}

	/**
	 * Adds a single public key entry to the a known_hosts file.
	 * This method is designed to be used in a {@link ServerHostKeyVerifier}.
	 * 
	 * @param knownHosts the file where the publickey entry will be appended.
	 * @param hostnames a list of hostname patterns - at least one most be specified. Check out the
	 *        OpenSSH sshd man page for a description of the pattern matching algorithm.
	 * @param serverHostKeyAlgorithm as passed to the {@link ServerHostKeyVerifier}.
	 * @param serverHostKey as passed to the {@link ServerHostKeyVerifier}.
	 * @throws IOException on failure parsing the key or writing to file
	 */
	public static void addHostkeyToFile(File knownHosts, String[] hostnames, String serverHostKeyAlgorithm,
			byte[] serverHostKey) throws IOException
	{
		if ((hostnames == null) || (hostnames.length == 0))
			throw new IllegalArgumentException("Need at least one hostname specification");

		if ((serverHostKeyAlgorithm == null) || (serverHostKey == null))
			throw new IllegalArgumentException();

		CharArrayWriter writer = new CharArrayWriter();
		
		for (int i = 0; i < hostnames.length; i++)
		{
			if (i != 0)
				writer.write(',');
			writer.write(hostnames[i]);
		}

		writer.write(' ');
		writer.write(serverHostKeyAlgorithm);
		writer.write(' ');
		writer.write(Base64.encode(serverHostKey));
		writer.write("\n");

		char[] entry = writer.toCharArray();
		
		RandomAccessFile raf = new RandomAccessFile(knownHosts, "rw");

		long len = raf.length();
		
		if (len > 0)
		{
			raf.seek(len - 1);
			int last = raf.read();
			if (last != '\n')
				raf.write('\n');
		}
		
		raf.write(new String(entry).getBytes("ISO-8859-1"));
		raf.close();
	}

	/**
	 * Generates a "raw" fingerprint of a hostkey.
	 * 
	 * @param type either "md5" or "sha1"
	 * @param keyType the type of key being fingerprinted
	 * @param hostkey the hostkey
	 * @return the raw fingerprint
	 */
	private static byte[] rawFingerPrint(String type, String keyType, byte[] hostkey)
	{
		Digest dig;

		if ("md5".equals(type))
		{
			dig = new MD5();
		}
		else if ("sha1".equals(type))
		{
			dig = new SHA1();
		}
		else
			throw new IllegalArgumentException("Unknown hash type " + type);

		boolean supportedKeyType = false;

		for (KeyAlgorithm<PublicKey, PrivateKey> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
			if (algorithm.getKeyFormat().equals(keyType)) {
				supportedKeyType = true;
				break;
			}
		}

		if (!supportedKeyType) {
			throw new IllegalArgumentException("Unknown key type " + keyType);
		}

		if (hostkey == null)
			throw new IllegalArgumentException("hostkey is null");

		dig.update(hostkey);
		byte[] res = new byte[dig.getDigestLength()];
		dig.digest(res);
		return res;
	}

	/**
	 * Convert a raw fingerprint to hex representation (XX:YY:ZZ...).
	 * @param fingerprint raw fingerprint
	 * @return the hex representation
	 */
	private static String rawToHexFingerprint(byte[] fingerprint)
	{
		final char[] alpha = "0123456789abcdef".toCharArray();

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < fingerprint.length; i++)
		{
			if (i != 0)
				sb.append(':');
			int b = fingerprint[i] & 0xff;
			sb.append(alpha[b >> 4]);
			sb.append(alpha[b & 15]);
		}

		return sb.toString();
	}

	/**
	 * Convert a raw fingerprint to bubblebabble representation.
	 * @param raw raw fingerprint
	 * @return the bubblebabble representation
	 */
	private static String rawToBubblebabbleFingerprint(byte[] raw)
	{
		final char[] v = "aeiouy".toCharArray();
		final char[] c = "bcdfghklmnprstvzx".toCharArray();

		StringBuilder sb = new StringBuilder();

		int seed = 1;

		int rounds = (raw.length / 2) + 1;

		sb.append('x');

		for (int i = 0; i < rounds; i++)
		{
			if (((i + 1) < rounds) || ((raw.length) % 2 != 0))
			{
				sb.append(v[(((raw[2 * i] >> 6) & 3) + seed) % 6]);
				sb.append(c[(raw[2 * i] >> 2) & 15]);
				sb.append(v[((raw[2 * i] & 3) + (seed / 6)) % 6]);

				if ((i + 1) < rounds)
				{
					sb.append(c[(((raw[(2 * i) + 1])) >> 4) & 15]);
					sb.append('-');
					sb.append(c[(((raw[(2 * i) + 1]))) & 15]);
					// As long as seed >= 0, seed will be >= 0 afterwards
					seed = ((seed * 5) + (((raw[2 * i] & 0xff) * 7) + (raw[(2 * i) + 1] & 0xff))) % 36;
				}
			}
			else
			{
				sb.append(v[seed % 6]); // seed >= 0, therefore index positive
				sb.append('x');
				sb.append(v[seed / 6]);
			}
		}

		sb.append('x');

		return sb.toString();
	}

	/**
	 * Convert a ssh2 key-blob into a human readable hex fingerprint.
	 * Generated fingerprints are identical to those generated by OpenSSH.
	 * <p>
	 * Example fingerprint: d0:cb:76:19:99:5a:03:fc:73:10:70:93:f2:44:63:47.

	 * @param keytype the type of key being fingerprinted
	 * @param publickey key blob
	 * @return Hex fingerprint
	 */
	public static String createHexFingerprint(String keytype, byte[] publickey)
	{
		byte[] raw = rawFingerPrint("md5", keytype, publickey);
		return rawToHexFingerprint(raw);
	}

	/**
	 * Convert a ssh2 key-blob into a human readable bubblebabble fingerprint.
	 * The used bubblebabble algorithm (taken from OpenSSH) generates fingerprints
	 * that are easier to remember for humans.
	 * <p>
	 * Example fingerprint: xofoc-bubuz-cazin-zufyl-pivuk-biduk-tacib-pybur-gonar-hotat-lyxux.
	 * 
	 * @param keytype the type of key being fingerprinted
	 * @param publickey key data
	 * @return Bubblebabble fingerprint
	 */
	public static String createBubblebabbleFingerprint(String keytype, byte[] publickey)
	{
		byte[] raw = rawFingerPrint("sha1", keytype, publickey);
		return rawToBubblebabbleFingerprint(raw);
	}
}
