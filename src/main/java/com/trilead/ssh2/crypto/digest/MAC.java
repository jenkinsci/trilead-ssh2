
package com.trilead.ssh2.crypto.digest;

/**
 * MAC. Replace by {@link MessageMac to support enchanced Mac algorithms}
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: MAC.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
/* This class is technically deprecated, but isn't marked as such since it's
* just the implementation with the public fields that's deprecated, rather than
* any of the methods in it
*/
public class MAC
{
	/**
	 * @deprecated May be null if a newer Mac algorithm is used
	 */
	@Deprecated
	Digest mac;

	/**
	 * @deprecated May be null if a newer Mac algorithm is used
	 */
	@Deprecated
	int size;

	/**
	 * Get mac list string [ ].
	 *
	 * @return the string [ ]
	 * @deprecated Use {@link MessageMac#getMacs()}
	 */
	@Deprecated
	public static String[] getMacList()
	{
		/* Higher Priority First */

		return new String[] { "hmac-sha1-96", "hmac-sha1", "hmac-md5-96", "hmac-md5" };
	}


	/**
	 * Check mac list.
	 *
	 * @param macs the macs
	 * @deprecated Use {@link MessageMac#checkMacs(String[])}
	 */
	@Deprecated
	public static void checkMacList(String[] macs)
	{
		for (int i = 0; i < macs.length; i++)
			getKeyLen(macs[i]);
	}


	/**
	 * Gets key len.
	 *
	 * @param type the type
	 * @return the key len
	 * @deprecated Use {@link MessageMac#getKeyLength(String)}
	 */
	@Deprecated
	public static int getKeyLen(String type)
	{
		if (type.equals("hmac-sha1"))
			return 20;
		if (type.equals("hmac-sha1-96"))
			return 20;
		if (type.equals("hmac-md5"))
			return 16;
		if (type.equals("hmac-md5-96"))
			return 16;
		throw new IllegalArgumentException("Unkown algorithm " + type);
	}

	/**
	 * @param type the MAC algorithm to use
	 * @param key the key to use in the MAC
	 * @deprecated use {@link MessageMac#MessageMac(String, byte[])}
	 */
	public MAC(String type, byte[] key)
	{
		if (type.equals("hmac-sha1"))
		{
			mac = new HMAC(new SHA1(), key, 20);
		}
		else if (type.equals("hmac-sha1-96"))
		{
			mac = new HMAC(new SHA1(), key, 12);
		}
		else if (type.equals("hmac-md5"))
		{
			mac = new HMAC(new MD5(), key, 16);
		}
		else if (type.equals("hmac-md5-96"))
		{
			mac = new HMAC(new MD5(), key, 12);
		}
		else
			return;

		size = mac.getDigestLength();
	}

	public void initMac(int seq)
	{
		mac.reset();
		mac.update((byte) (seq >> 24));
		mac.update((byte) (seq >> 16));
		mac.update((byte) (seq >> 8));
		mac.update((byte) (seq));
	}

	public void update(byte[] packetdata, int off, int len)
	{
		mac.update(packetdata, off, len);
	}

	public void getMac(byte[] out, int off)
	{
		mac.digest(out, off);
	}

	public int size()
	{
		return size;
	}
}
