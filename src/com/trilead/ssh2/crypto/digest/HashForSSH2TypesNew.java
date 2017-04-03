package com.trilead.ssh2.crypto.digest;

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

/**
 * HashForSSH2TypesNew.
 */
public class HashForSSH2TypesNew
{
	private MessageDigest md;

	public HashForSSH2TypesNew(String type)
	{
		try {
			md = MessageDigest.getInstance(type);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unsupported algorithm " + type);
		}
	}

	public void updateByte(byte b)
	{
		/* HACK - to test it with J2ME */
		byte[] tmp = new byte[1];
		tmp[0] = b;
		md.update(tmp);
	}

	public void updateBytes(byte[] b)
	{
		md.update(b);
	}

	public void updateUINT32(int v)
	{
		md.update((byte) (v >> 24));
		md.update((byte) (v >> 16));
		md.update((byte) (v >> 8));
		md.update((byte) (v));
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
		md.reset();
	}

	public int getDigestLength()
	{
		return md.getDigestLength();
	}

	public byte[] getDigest() throws IOException
	{
		byte[] tmp = new byte[md.getDigestLength()];
		getDigest(tmp);
		return tmp;
	}

	public void getDigest(byte[] out) throws IOException
	{
		getDigest(out, 0);
	}

	public void getDigest(byte[] out, int off) throws IOException
	{
		try {
			md.digest(out, off, out.length - off);
		} catch (DigestException e) {
			throw new IOException("Unable to digest", e);
		}
	}
}
