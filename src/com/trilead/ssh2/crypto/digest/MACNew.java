package com.trilead.ssh2.crypto.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * MACNew.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: MACNew.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public final class MACNew
{
	private enum Hmac
	{
		HMAC_MD5("hmac-md5", "HmacMD5", 16), // http://tools.ietf.org/html/rfc4253
		HMAC_MD5_96("hmac-md5-96", "HmacMD5", 16), // http://tools.ietf.org/html/rfc4253
		HMAC_SHA1("hmac-sha1", "HmacSHA1", 20), // http://tools.ietf.org/html/rfc4253
		HMAC_SHA1_96("hmac-sha1-96", "HmacSHA1", 20), // http://tools.ietf.org/html/rfc4253
		HMAC_SHA2_256("hmac-sha2-256", "HmacSHA256", 32), // http://tools.ietf.org/html/rfc6668
		HMAC_SHA2_512("hmac-sha2-512", "HmacSHA512", 64); // http://tools.ietf.org/html/rfc6668

		private String type;
		private String algorithm;
		private int length;

		Hmac(String type, String algorithm, int length) 
		{
			this.type = type;
			this.algorithm = algorithm;
			this.length = length;
		}

		private static Hmac getHmac(String type) 
		{
			try 
			{
				return Hmac.valueOf(type.replaceAll("-", "_").toUpperCase());
			} 
			catch (Exception e) 
			{
				throw new IllegalArgumentException("Unkown algorithm " + type);
			}
		}
	}

	private static final String[] PRIORITIZED_MAC_LIST = { Hmac.HMAC_SHA2_256.type, Hmac.HMAC_SHA2_512.type,
			Hmac.HMAC_SHA1_96.type, Hmac.HMAC_SHA1.type, Hmac.HMAC_MD5_96.type, Hmac.HMAC_MD5.type };

	Mac mac;
	int outSize;
	int macSize;
	byte[] buffer;

	public final static String[] getMacList() 
	{
		return PRIORITIZED_MAC_LIST;
	}

	public final static void checkMacList(String[] macs) 
	{
		for (int i = 0; i < macs.length; i++)
			getKeyLen(macs[i]);
	}

	public final static int getKeyLen(String type) 
	{
		return Hmac.getHmac(type).length;
	}

	public MACNew(String type, byte[] key) 
	{
		try 
		{
			mac = Mac.getInstance(Hmac.getHmac(type).algorithm);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new IllegalArgumentException("Unknown algorithm " + type, e);
		}

		macSize = mac.getMacLength();
		if (type.endsWith("-256")) {
			outSize = 32;
			buffer = new byte[macSize];
		} else if (type.endsWith("-512")) {
			outSize = 64;
			buffer = new byte[macSize];
		} else if (type.endsWith("-96")) {
			outSize = 12;
			buffer = new byte[macSize];
		} else {
			outSize = macSize;
			buffer = null;
		}

		try 
		{
			mac.init(new SecretKeySpec(key, type));
		} 
		catch (InvalidKeyException e) 
		{
			throw new IllegalArgumentException(e);
		}
	}

	public final void initMac(int seq) 
	{
		mac.reset();
		mac.update((byte) (seq >> 24));
		mac.update((byte) (seq >> 16));
		mac.update((byte) (seq >> 8));
		mac.update((byte) (seq));
	}

	public final void update(byte[] packetdata, int off, int len)
	{
		mac.update(packetdata, off, len);
	}

	public final void getMac(byte[] out, int off) 
	{
		try
		{
			if (buffer != null) 
			{
				mac.doFinal(buffer, 0);
				System.arraycopy(buffer, 0, out, off, out.length - off);
			} 
			else 
			{
				mac.doFinal(out, off);
			}
		} 
		catch (ShortBufferException e) 
		{
			throw new IllegalStateException(e);
		}
	}

	public final int size() 
	{
		return outSize;
	}
}
