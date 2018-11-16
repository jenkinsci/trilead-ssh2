package com.trilead.ssh2.transport;


import java.math.BigInteger;

import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.crypto.dh.DhExchange;
import com.trilead.ssh2.crypto.dh.DhGroupExchange;
import com.trilead.ssh2.packets.PacketKexInit;

/**
 * KexState.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: KexState.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class KexState
{
	public PacketKexInit localKEX;
	public PacketKexInit remoteKEX;
	public NegotiatedParameters np;
	public int state = 0;

	public BigInteger K;
	public byte[] H;
	
	public byte[] hostkey;
	
	public DhExchange dhx;
	public DhGroupExchange dhgx;
	public DHGexParameters dhgexParameters;
	private String hashAlgorithm;

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getHashAlgorithm() {
    	return hashAlgorithm;
	}
}
