
package com.trilead.ssh2.crypto;

import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.digest.MessageMac;
import com.trilead.ssh2.jenkins.FilterEncrytionAlgorithms;
import com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms;
import com.trilead.ssh2.jenkins.FilterKexAlgorithms;
import com.trilead.ssh2.jenkins.FilterMacAlgorithms;
import com.trilead.ssh2.transport.KexManager;


/**
 * CryptoWishList.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: CryptoWishList.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class CryptoWishList
{
	public String[] kexAlgorithms = FilterKexAlgorithms.filter(KexManager.getDefaultKexAlgorithmList());
	public String[] serverHostKeyAlgorithms = FilterHostKeyAlgorithms.filter(KexManager.getDefaultServerHostkeyAlgorithmList());
	public String[] c2s_enc_algos = FilterEncrytionAlgorithms.filter(BlockCipherFactory.getDefaultCipherList());
	public String[] s2c_enc_algos = FilterEncrytionAlgorithms.filter(BlockCipherFactory.getDefaultCipherList());
	public String[] c2s_mac_algos = FilterMacAlgorithms.filter(MessageMac.getMacs());
	public String[] s2c_mac_algos = FilterMacAlgorithms.filter(MessageMac.getMacs());
}