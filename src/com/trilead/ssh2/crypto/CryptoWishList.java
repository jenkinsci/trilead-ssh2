
package com.trilead.ssh2.crypto;

import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.digest.MACNew;
import com.trilead.ssh2.transport.KexManagerNew;


/**
 * CryptoWishList.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: CryptoWishList.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class CryptoWishList
{
	public String[] kexAlgorithms = KexManagerNew.getDefaultKexAlgorithmList();
	public String[] serverHostKeyAlgorithms = KexManagerNew.getDefaultServerHostkeyAlgorithmList();
	public String[] c2s_enc_algos = BlockCipherFactory.getDefaultCipherList();
	public String[] s2c_enc_algos = BlockCipherFactory.getDefaultCipherList();
	public String[] c2s_mac_algos = MACNew.getMacList();
	public String[] s2c_mac_algos = MACNew.getMacList();
}
