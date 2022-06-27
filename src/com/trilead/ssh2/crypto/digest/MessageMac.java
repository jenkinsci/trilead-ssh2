
package com.trilead.ssh2.crypto.digest;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public final class MessageMac extends MAC {

	private final Mac messageMac;
	private boolean encryptThenMac = false;
	private final byte[] buffer;
	private final int outSize;

	public MessageMac(String type, byte[] key) {
		super(type, key);

		try {
			messageMac = Mac.getInstance(Hmac.getHmac(type).getAlgorithm());
			
			int macSize = messageMac.getMacLength();
			
			if (type.endsWith("-96")) {
				outSize = 12;
				buffer = new byte[macSize];
			} else {
				outSize = macSize;
				buffer = null;
			}
			
			encryptThenMac = Hmac.getHmac(type).isEtm();
			messageMac.init(new SecretKeySpec(key, type));
		} catch (GeneralSecurityException ex) {
			throw new IllegalArgumentException("Could not create Mac", ex);
		}
	}


	public static String[] getMacs() {
		List<String> macList = new ArrayList<String>();
		for (Hmac hmac : Hmac.values()) {
			macList.add(0, hmac.getType());
		}
		return macList.toArray(new String[macList.size()]);
	}

	public static void checkMacs(String[] macs) {
		for (String mac : macs) {
			Hmac.getHmac(mac);
		}
	}

	public static int getKeyLength(String type) {
		return Hmac.getHmac(type).getLength();
	}

	public final void initMac(int seq) {
		messageMac.reset();
		messageMac.update((byte) (seq >> 24));
		messageMac.update((byte) (seq >> 16));
		messageMac.update((byte) (seq >> 8));
		messageMac.update((byte) (seq));
	}

	public final void update(byte[] packetdata, int off, int len)
	{
		messageMac.update(packetdata, off, len);
	}

	public final void getMac(byte[] out, int off) {
		try {
			if (buffer != null) {
				messageMac.doFinal(buffer, 0);
				System.arraycopy(buffer, 0, out, off, out.length - off);
			} else {
				messageMac.doFinal(out, off);
			}
		} catch (ShortBufferException e) {
			throw new IllegalStateException(e);
		}
	}

	public final int size()
	{
		return outSize;
	}
	
	public final boolean isEncryptThenMac() 
	{
		return encryptThenMac;
	}

	private enum Hmac {
		HMAC_MD5_96("hmac-md5-96", "HmacMD5", 16,false),
		HMAC_MD5("hmac-md5", "HmacMD5", 16,false),
		HMAC_SHA1_96("hmac-sha1-96", "HmacSHA1", 20,false),
		HMAC_SHA1("hmac-sha1", "HmacSHA1", 20,false),
		HMAC_SHA2_256("hmac-sha2-256", "HmacSHA256", 32,false),
		HMAC_SHA2_512("hmac-sha2-512", "HmacSHA512", 64,false),
		HMAC_SHA2_256_ETM("hmac-sha2-256-etm@openssh.com", "HmacSHA256", 32,true),
		HMAC_SHA2_512_ETM("hmac-sha2-512-etm@openssh.com", "HmacSHA512", 64,true);

		private String type;
		private String algorithm;
		private int length;
		private boolean isEtm;

		Hmac(String type, String algorithm, int length,boolean isEtm) {
			this.type = type;
			this.algorithm = algorithm;
			this.length = length;
			this.isEtm = isEtm;
		}

		public String getType() {
			return type;
		}

		public String getAlgorithm() {
			return algorithm;
		}

		public int getLength() {
			return length;
		}
		
		public boolean isEtm() {
			return isEtm;
		}

		private static Hmac getHmac(String type) {
			for (Hmac hmac : values()) {
				if (hmac.getType().equals(type)) {
					return hmac;
				}
			}
			throw new IllegalArgumentException("Invalid HMAC type: " + type);
		}
	}
}
