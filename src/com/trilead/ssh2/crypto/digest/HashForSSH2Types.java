
package com.trilead.ssh2.crypto.digest;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * HashForSSH2Types.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: HashForSSH2Types.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class HashForSSH2Types
{

	/**
	 * Overwriting this value will not cause the result of the
	 * digest to change
	 * @deprecated the actual message digest is held in a private field
	 */
	@Deprecated
	Digest md;
	
	private final Digest messageDigest;
	
	

	public HashForSSH2Types(Digest md)
	{
		super();
		this.md = md;
		this.messageDigest = md;
	}

	public HashForSSH2Types(String type)
	{
		this(new JreMessageDigestWrapper(createMessageDigest(type)));
	}

	private static MessageDigest createMessageDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (GeneralSecurityException ex) {
			throw new IllegalArgumentException("Could not get Message digest instance", ex);
		}
	}

	public void updateByte(byte b)
	{
		/* HACK - to test it with J2ME */
		byte[] tmp = new byte[1];
		tmp[0] = b;
		messageDigest.update(tmp);
	}

	public void updateBytes(byte[] b)
	{
		messageDigest.update(b);
	}

	public void updateUINT32(int v)
	{
		messageDigest.update((byte) (v >> 24));
		messageDigest.update((byte) (v >> 16));
		messageDigest.update((byte) (v >> 8));
		messageDigest.update((byte) (v));
	}

	public void updateByteString(byte[] b)
	{
		updateUINT32(b.length);
		updateBytes(b);
	}

	public void updateBigInt(BigInteger b)
	{
		updateByteString(b.toByteArray());
	}

	public void reset()
	{
		messageDigest.reset();
	}

	public int getDigestLength()
	{
		return messageDigest.getDigestLength();
	}

	public byte[] getDigest()
	{
		byte[] tmp = new byte[messageDigest.getDigestLength()];
		getDigest(tmp);
		return tmp;
	}

	public void getDigest(byte[] out)
	{
		getDigest(out, 0);
	}

	public void getDigest(byte[] out, int off)
	{
		messageDigest.digest(out, off);
	}
}
