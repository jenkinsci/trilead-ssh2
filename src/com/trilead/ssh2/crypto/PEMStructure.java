
package com.trilead.ssh2.crypto;

/**
 * Parsed PEM structure.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: PEMStructure.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */

public class PEMStructure
{
	int pemType;
	String dekInfo[];
	String procType[];
	byte[] data;

	public byte[] getData() {
		return data;
	}
}