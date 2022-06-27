
package com.trilead.ssh2.crypto.cipher;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * CipherInputStream.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: CipherInputStream.java,v 1.1 2007/10/15 12:49:55 cplattne Exp $
 */
public class CipherInputStream
{
	private BlockCipher currentCipher;
	private final BufferedInputStream bi;
	private byte[] buffer;
	private byte[] enc;
	private int blockSize;
	private int pos;

	public CipherInputStream(BlockCipher tc, InputStream bi)
	{
		if (bi instanceof BufferedInputStream) {
			this.bi = (BufferedInputStream) bi;
		} else {
			this.bi = new BufferedInputStream(bi);
		}
		changeCipher(tc);
	}

	public void changeCipher(BlockCipher bc)
	{
		this.currentCipher = bc;
		blockSize = bc.getBlockSize();
		buffer = new byte[blockSize];
		enc = new byte[blockSize];
		pos = blockSize;
	}

	private void getBlock() throws IOException
	{
		int n = 0;
		while (n < blockSize)
		{
			int len = bi.read(enc, n, blockSize - n);
			if (len < 0)
				throw new IOException("Cannot read full block, EOF reached.");
			n += len;
		}

		try
		{
			currentCipher.transformBlock(enc, 0, buffer, 0);
		}
		catch (Exception e)
		{
			throw new IOException("Error while decrypting block.");
		}
		pos = 0;
	}

	public int read(byte[] dst) throws IOException
	{
		return read(dst, 0, dst.length);
	}

	public int read(byte[] dst, int off, int len) throws IOException
	{
		int count = 0;

		while (len > 0)
		{
			if (pos >= blockSize)
				getBlock();

			int avail = blockSize - pos;
			int copy = Math.min(avail, len);
			System.arraycopy(buffer, pos, dst, off, copy);
			pos += copy;
			off += copy;
			len -= copy;
			count += copy;
		}
		return count;
	}

	public int read() throws IOException
	{
		if (pos >= blockSize)
		{
			getBlock();
		}
		return buffer[pos++] & 0xff;
	}

	public int readPlain(byte[] b, int off, int len) throws IOException
	{
		if (pos != blockSize)
			throw new IOException("Cannot read plain since crypto buffer is not aligned.");
		int n = 0;
		while (n < len)
		{
			int cnt = bi.read(b, off + n, len - n);
			if (cnt < 0)
				throw new IOException("Cannot fill buffer, EOF reached.");
			n += cnt;
		}
		return n;
	}

	public int peekPlain(byte[] b, int off, int len) throws IOException
	{
		if (pos != blockSize)
			throw new IOException("Cannot read plain since crypto buffer is not aligned.");
		int n = 0;

		bi.mark(len);
		try {
			while (n < len) {
				int cnt = bi.read(b, off + n, len - n);
				if (cnt < 0)
					throw new IOException("Cannot fill buffer, EOF reached.");
				n += cnt;
			}
		} finally {
			bi.reset();
		}

		return n;
	}
}
