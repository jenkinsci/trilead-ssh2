package com.trilead.ssh2.transport;


import java.math.BigInteger;

import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.crypto.dh.DhGroupExchange;
import com.trilead.ssh2.crypto.dh.GenericDhExchange;
import com.trilead.ssh2.packets.PacketKexInit;

/**
 * KexStateNew.
 */
public class KexStateNew
{
	public PacketKexInit localKEX;
	public PacketKexInit remoteKEX;
	public NegotiatedParameters np;
	public int state = 0;

	public BigInteger K;
	public byte[] H;

	public byte[] hostkey;

	public String hashAlgo;
	public GenericDhExchange dhx;
	public DhGroupExchange dhgx;
	public DHGexParameters dhgexParameters;
}
