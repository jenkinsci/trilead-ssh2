
package com.trilead.ssh2.crypto.dh;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.trilead.ssh2.crypto.digest.HashForSSH2Types;
import com.trilead.ssh2.log.Logger;


/**
 * DhExchange.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: DhExchange.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public abstract class GenericDhExchange
{
	private static final Logger log = Logger.getLogger(GenericDhExchange.class);

	/* Shared secret */

	BigInteger sharedSecret;

	protected GenericDhExchange()
	{
	}

	public static GenericDhExchange getInstance(String algo) {
		if (Curve25519Exchange.NAME.equals(algo) || Curve25519Exchange.ALT_NAME.equals(algo)) {
			return new Curve25519Exchange();
		}
		if (algo.startsWith("ecdh-sha2-")) {
			return new EcDhExchange();
		} else {
			return new DhExchange();
		}
	}

	public abstract void init(String name) throws IOException;

	/**
	 * @return Returns the e (public value)
	 * @throws IllegalStateException
	 */
	public abstract byte[] getE();

	/**
	 * @return Returns the server's e (public value)
	 * @throws IllegalStateException
	 */
	protected abstract byte[] getServerE();

	/**
	 * @return Returns the shared secret k.
	 * @throws IllegalStateException
	 */
	public BigInteger getK()
	{
		if (sharedSecret == null)
			throw new IllegalStateException("Shared secret not yet known, need f first!");

		return sharedSecret;
	}

	/**
	 * @param f
	 */
	public abstract void setF(byte[] f) throws IOException;

	public byte[] calculateH(byte[] clientversion, byte[] serverversion, byte[] clientKexPayload,
			byte[] serverKexPayload, byte[] hostKey) throws UnsupportedEncodingException
	{
		HashForSSH2Types hash = new HashForSSH2Types(getHashAlgo());

		if (log.isEnabled())
		{
			log.log(90, "Client: '" + new String(clientversion) + "'");
			log.log(90, "Server: '" + new String(serverversion) + "'");
		}

		hash.updateByteString(clientversion);
		hash.updateByteString(serverversion);
		hash.updateByteString(clientKexPayload);
		hash.updateByteString(serverKexPayload);
		hash.updateByteString(hostKey);
		hash.updateByteString(getE());
		hash.updateByteString(getServerE());
		hash.updateBigInt(sharedSecret);

		return hash.getDigest();
	}

	public abstract String getHashAlgo();

}
