
package com.trilead.ssh2.crypto;

import com.trilead.ssh2.crypto.cipher.JreCipherWrapper;
import com.trilead.ssh2.signature.DSAPrivateKey;
import com.trilead.ssh2.signature.KeyAlgorithm;
import com.trilead.ssh2.signature.KeyAlgorithmManager;
import com.trilead.ssh2.signature.RSAPrivateKey;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PEM Support.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: PEMDecoder.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public class PEMDecoder
{
	private static final Logger LOGGER = Logger.getLogger(PEMDecoder.class.getName());
	private static final int PEM_RSA_PRIVATE_KEY = 1;
	private static final int PEM_DSA_PRIVATE_KEY = 2;

	private static int hexToInt(char c)
	{
		if ((c >= 'a') && (c <= 'f'))
		{
			return (c - 'a') + 10;
		}

		if ((c >= 'A') && (c <= 'F'))
		{
			return (c - 'A') + 10;
		}

		if ((c >= '0') && (c <= '9'))
		{
			return (c - '0');
		}

		throw new IllegalArgumentException("Need hex char");
	}

	private static byte[] hexToByteArray(String hex)
	{
		if (hex == null)
			throw new IllegalArgumentException("null argument");

		if ((hex.length() % 2) != 0)
			throw new IllegalArgumentException("Uneven string length in hex encoding.");

		byte decoded[] = new byte[hex.length() / 2];

		for (int i = 0; i < decoded.length; i++)
		{
			int hi = hexToInt(hex.charAt(i * 2));
			int lo = hexToInt(hex.charAt((i * 2) + 1));

			decoded[i] = (byte) (hi * 16 + lo);
		}

		return decoded;
	}

	/**
	 * @deprecated Use PBE ciphers
	 */
	public static byte[] generateKeyFromPasswordSaltWithMD5(byte[] password, byte[] salt, int keyLen)
			throws IOException
	{
		if (salt.length < 8)
			throw new IllegalArgumentException("Salt needs to be at least 8 bytes for key generation.");

		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}

		byte[] key = new byte[keyLen];
		byte[] tmp = new byte[md5.getDigestLength()];

		while (true)
		{
			md5.update(password, 0, password.length);
			md5.update(salt, 0, 8); // ARGH we only use the first 8 bytes of the
			// salt in this step.
			// This took me two hours until I got AES-xxx running.

			int copy = (keyLen < tmp.length) ? keyLen : tmp.length;

			try {
				md5.digest(tmp, 0, tmp.length);
			} catch (DigestException e) {
				throw new IllegalArgumentException(e);
			}

			System.arraycopy(tmp, 0, key, key.length - keyLen, copy);

			keyLen -= copy;

			if (keyLen == 0)
				return key;

			md5.update(tmp, 0, tmp.length);
		}
	}

	private static byte[] removePadding(byte[] buff, int blockSize) throws IOException
	{
		/* Removes RFC 1423/PKCS #7 padding */

		int rfc_1423_padding = buff[buff.length - 1] & 0xff;

		if ((rfc_1423_padding < 1) || (rfc_1423_padding > blockSize))
			throw new IOException("Decrypted PEM has wrong padding, did you specify the correct password?");

		for (int i = 2; i <= rfc_1423_padding; i++)
		{
			if (buff[buff.length - i] != rfc_1423_padding)
				throw new IOException("Decrypted PEM has wrong padding, did you specify the correct password?");
		}

		byte[] tmp = new byte[buff.length - rfc_1423_padding];
		System.arraycopy(buff, 0, tmp, 0, buff.length - rfc_1423_padding);
		return tmp;
	}

	private static PEMStructure parsePEM(char[] pem) throws IOException
	{
		PEMStructure ps = new PEMStructure();

		String line;

		BufferedReader br = new BufferedReader(new CharArrayReader(pem));

		String endLine;

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, '-----BEGIN...' missing");

			line = line.trim();

			if (line.startsWith("-----BEGIN DSA PRIVATE KEY-----"))
			{
				endLine = "-----END DSA PRIVATE KEY-----";
				ps.pemType = PEM_DSA_PRIVATE_KEY;
				break;
			}

			if (line.startsWith("-----BEGIN RSA PRIVATE KEY-----"))
			{
				endLine = "-----END RSA PRIVATE KEY-----";
				ps.pemType = PEM_RSA_PRIVATE_KEY;
				break;
			}
		}

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			int sem_idx = line.indexOf(':');

			if (sem_idx == -1)
				break;

			String name = line.substring(0, sem_idx + 1);
			String value = line.substring(sem_idx + 1);

			String values[] = value.split(",");

			for (int i = 0; i < values.length; i++)
				values[i] = values[i].trim();

			// Proc-Type: 4,ENCRYPTED
			// DEK-Info: DES-EDE3-CBC,579B6BE3E5C60483

			if ("Proc-Type:".equals(name))
			{
				ps.procType = values;
				continue;
			}

			if ("DEK-Info:".equals(name))
			{
				ps.dekInfo = values;
				continue;
			}
			/* Ignore line */
		}

		StringBuilder keyData = new StringBuilder();

		while (true)
		{
			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			if (line.startsWith(endLine))
				break;

			keyData.append(line);

			line = br.readLine();
		}

		char[] pem_chars = new char[keyData.length()];
		keyData.getChars(0, pem_chars.length, pem_chars, 0);

		ps.data = Base64.decode(pem_chars);

		if (ps.data.length == 0)
			throw new IOException("Invalid PEM structure, no data available");

		return ps;
	}



	private static PEMStructure parsePEM(char[] pem, CertificateDecoder certificateDecoder) throws IOException
	{
		PEMStructure ps = new PEMStructure();

		String line;

		BufferedReader br = new BufferedReader(new CharArrayReader(pem));

		String endLine;

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, '-----BEGIN...' missing");

			line = line.trim();

			if (line.startsWith(certificateDecoder.getStartLine()))
			{
				endLine = certificateDecoder.getEndLine();
				break;
			}

		}

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			int sem_idx = line.indexOf(':');

			if (sem_idx == -1)
				break;

			String name = line.substring(0, sem_idx + 1);
			String value = line.substring(sem_idx + 1);

			String values[] = value.split(",");

			for (int i = 0; i < values.length; i++)
				values[i] = values[i].trim();

			// Proc-Type: 4,ENCRYPTED
			// DEK-Info: DES-EDE3-CBC,579B6BE3E5C60483

			if ("Proc-Type:".equals(name))
			{
				ps.procType = values;
				continue;
			}

			if ("DEK-Info:".equals(name))
			{
				ps.dekInfo = values;
				continue;
			}
			/* Ignore line */
		}

		StringBuilder keyData = new StringBuilder();

		while (true)
		{
			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			if (line.startsWith(endLine))
				break;

			keyData.append(line);

			line = br.readLine();
		}

		char[] pem_chars = new char[keyData.length()];
		keyData.getChars(0, pem_chars.length, pem_chars, 0);

		ps.data = Base64.decode(pem_chars);

		if (ps.data.length == 0)
			throw new IOException("Invalid PEM structure, no data available");

		return ps;
	}

	private static void decryptPEM(PEMStructure ps, char[] pw) throws IOException
	{
		if (ps.dekInfo == null)
			throw new IOException("Broken PEM, no mode and salt given, but encryption enabled");

		if (ps.dekInfo.length != 2)
			throw new IOException("Broken PEM, DEK-Info is incomplete!");

		String algo = ps.dekInfo[0];
		byte[] salt = hexToByteArray(ps.dekInfo[1]);

		JreCipherWrapper bc;

		switch (algo) {
			case "DES-EDE3-CBC":
				bc = JreCipherWrapper.getInstance("PBEWithMD5AndTripleDES", new PBEParameterSpec(salt, 1));
				bc.init(false, new PBEKeySpec(pw, salt, 1, 24));
				break;
			case "DES-CBC":
				bc = JreCipherWrapper.getInstance("PBEWithMD5AndDES", new PBEParameterSpec(salt, 1));
				bc.init(false, new PBEKeySpec(pw, salt, 1, 8));
				break;
			case "AES-128-CBC":
				bc = JreCipherWrapper.getInstance("PBEWithMD5AndAES_128", new PBEParameterSpec(salt, 1));
				bc.init(false, new PBEKeySpec(pw, salt, 1,16));
				break;
			case "AES-192-CBC":
				bc = JreCipherWrapper.getInstance("PBEWithMD5AndAES_192", new PBEParameterSpec(salt, 1));
				bc.init(false, new PBEKeySpec(pw, salt, 1, 24));
				break;
			case "AES-256-CBC":
				bc = JreCipherWrapper.getInstance("PBEWithMD5AndAES_256", new PBEParameterSpec(salt, 1));
				bc.init(false, new PBEKeySpec(pw, salt, 1, 32));
				break;
			default:
				throw new IOException("Cannot decrypt PEM structure, unknown cipher " + algo);
		}

		if ((ps.data.length % bc.getBlockSize()) != 0)
			throw new IOException("Invalid PEM structure, size of encrypted block is not a multiple of "
					+ bc.getBlockSize());

		/* Now decrypt the content */

		byte[] dz = new byte[ps.data.length];

		for (int i = 0; i < ps.data.length / bc.getBlockSize(); i++)
		{
			bc.transformBlock(ps.data, i * bc.getBlockSize(), dz, i * bc.getBlockSize());
		}

		/* Now check and remove RFC 1423/PKCS #7 padding */

		dz = removePadding(dz, bc.getBlockSize());

		ps.data = dz;
		ps.dekInfo = null;
		ps.procType = null;
	}

	public static boolean isPEMEncrypted(PEMStructure ps) throws IOException
	{
		if (ps.procType == null)
			return false;

		if (ps.procType.length != 2)
			throw new IOException("Unknown Proc-Type field.");

		if (!"4".equals(ps.procType[0]))
			throw new IOException("Unknown Proc-Type field (" + ps.procType[0] + ")");

		return ("ENCRYPTED".equals(ps.procType[1]));
	}

	@Deprecated
	public static Object decode(char[] pem, String password) throws IOException
	{
		PEMStructure ps = parsePEM(pem);

		if (isPEMEncrypted(ps))
		{
			if (password == null)
				throw new IOException("PEM is encrypted, but no password was specified");

			decryptPEM(ps, password.toCharArray());
		}

		if (ps.pemType == PEM_DSA_PRIVATE_KEY)
		{
			SimpleDERReader dr = new SimpleDERReader(ps.data);

			byte[] seq = dr.readSequenceAsByteArray();

			if (dr.available() != 0)
				throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

			dr.resetInput(seq);

			BigInteger version = dr.readInt();

			if (version.compareTo(BigInteger.ZERO) != 0)
				throw new IOException("Wrong version (" + version + ") in DSA PRIVATE KEY DER stream.");

			BigInteger p = dr.readInt();
			BigInteger q = dr.readInt();
			BigInteger g = dr.readInt();
			BigInteger y = dr.readInt();
			BigInteger x = dr.readInt();

			if (dr.available() != 0)
				throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

			return new DSAPrivateKey(p, q, g, y, x);
		}

		if (ps.pemType == PEM_RSA_PRIVATE_KEY)
		{
			SimpleDERReader dr = new SimpleDERReader(ps.data);

			byte[] seq = dr.readSequenceAsByteArray();

			if (dr.available() != 0)
				throw new IOException("Padding in RSA PRIVATE KEY DER stream.");

			dr.resetInput(seq);

			BigInteger version = dr.readInt();

			if ((version.compareTo(BigInteger.ZERO) != 0) && (version.compareTo(BigInteger.ONE) != 0))
				throw new IOException("Wrong version (" + version + ") in RSA PRIVATE KEY DER stream.");

			BigInteger n = dr.readInt();
			BigInteger e = dr.readInt();
			BigInteger d = dr.readInt();

			return new RSAPrivateKey(d, e, n);
		}

		throw new IOException("PEM problem: it is of unknown type");
	}


	public static KeyPair decodeKeyPair(char[] pem, String password) throws IOException
	{

		for (KeyAlgorithm<?, ?> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
			for (CertificateDecoder decoder : algorithm.getCertificateDecoders()) {
				try {
					PEMStructure ps = parsePEM(pem, decoder);

					if (isPEMEncrypted(ps)) {
						if (password == null)
							throw new IOException("PEM is encrypted, but no password was specified");

						decryptPEM(ps, password.toCharArray());
					}

					return decoder.createKeyPair(ps, password);
				} catch (IOException ex) {
					LOGGER.log(Level.FINE, "Could not decode PEM Key using current decoder: " + decoder.getClass().getName(), ex);
					// we couldn't decode the input, try another decoder
				}
			}
		}
		throw new IOException("PEM problem: it is of unknown type");
	}

}
