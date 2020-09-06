
package com.trilead.ssh2.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * Parsed PEM structure.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: PEMStructure.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */

public class PEMStructure
{
	int pemType;
	public String[] dekInfo;
	String procType[];
	byte[] data;

	public byte[] getData() {
		return data;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		PEMStructure that = (PEMStructure) o;
		return pemType == that.pemType
		       && Arrays.equals(dekInfo, that.dekInfo)
		       && Arrays.equals(procType, that.procType)
		       && Arrays.equals(data, that.data);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(pemType);
		result = 31 * result + Arrays.hashCode(dekInfo);
		result = 31 * result + Arrays.hashCode(procType);
		result = 31 * result + Arrays.hashCode(data);
		return result;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("PEMStructure{");
		sb.append("pemType=").append(pemType);
		sb.append(", dekInfo=").append(Arrays.toString(dekInfo));
		sb.append(", procType=").append(Arrays.toString(procType));
		sb.append(", data=").append(java.util.Base64.getEncoder().encodeToString(data));
		sb.append(", data.length=").append(data.length);
		sb.append('}');
		return sb.toString();
	}
}