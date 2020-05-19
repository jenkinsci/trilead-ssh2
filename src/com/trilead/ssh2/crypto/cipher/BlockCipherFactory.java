
package com.trilead.ssh2.crypto.cipher;

import javax.crypto.spec.IvParameterSpec;
import java.util.Vector;

/**
 * BlockCipherFactory.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: BlockCipherFactory.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public class BlockCipherFactory
{
	static class CipherEntry
	{
		String type;
		String algorithm;
		int blocksize;
		int keysize;

		public CipherEntry(String type, String algorithm, int blockSize, int keySize)
		{
			this.type = type;
			this.algorithm = algorithm;
			this.blocksize = blockSize;
			this.keysize = keySize;
		}
	}

	static Vector<CipherEntry> ciphers = new Vector<>();

	static
	{
		/* Higher Priority First */

		ciphers.addElement(new CipherEntry("aes256-ctr", "AES/CTR/NoPadding", 16, 32));
		ciphers.addElement(new CipherEntry("aes192-ctr", "AES/CTR/NoPadding", 16, 24));
		ciphers.addElement(new CipherEntry("aes128-ctr", "AES/CTR/NoPadding", 16, 16));
		ciphers.addElement(new CipherEntry("blowfish-ctr", "Blowfish/CTR/NoPadding", 8, 16));

		ciphers.addElement(new CipherEntry("aes256-cbc", "AES/CBC/NoPadding", 16, 32));
		ciphers.addElement(new CipherEntry("aes192-cbc", "AES/CBC/NoPadding", 16, 24));
		ciphers.addElement(new CipherEntry("aes128-cbc", "AES/CBC/NoPadding", 16, 16));
		ciphers.addElement(new CipherEntry("blowfish-cbc", "Blowfish/CBC/NoPadding", 8, 16));
		
		ciphers.addElement(new CipherEntry("3des-ctr", "DESede/CTR/NoPadding", 8, 24));
		ciphers.addElement(new CipherEntry("3des-cbc", "DESede/CBC/NoPadding", 8, 24));
	}

	public static String[] getDefaultCipherList()
	{
		String[] list = new String[ciphers.size()];
		for (int i = 0; i < ciphers.size(); i++)
		{
			CipherEntry ce = ciphers.elementAt(i);
			list[i] = ce.type;
		}
		return list;
	}

	public static void checkCipherList(String[] cipherCandidates)
	{
		for (int i = 0; i < cipherCandidates.length; i++)
			getEntry(cipherCandidates[i]);
	}

	public static BlockCipher createCipher(String type, boolean encrypt, byte[] key, byte[] iv)
	{
		CipherEntry ce = getEntry(type);
		BlockCipher bc = JreCipherWrapper.getInstance(ce.algorithm, new IvParameterSpec(iv));
		bc.init(encrypt, key);
		return bc;
	}

	private static CipherEntry getEntry(String type)
	{
		for (int i = 0; i < ciphers.size(); i++)
		{
			CipherEntry ce = ciphers.elementAt(i);
			if (ce.type.equals(type))
				return ce;
		}
		throw new IllegalArgumentException("Unkown algorithm " + type);
	}

	public static int getBlockSize(String type)
	{
		CipherEntry ce = getEntry(type);
		return ce.blocksize;
	}

	public static int getKeySize(String type)
	{
		CipherEntry ce = getEntry(type);
		return ce.keysize;
	}
}
