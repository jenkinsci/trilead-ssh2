/*
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * a.) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * b.) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * c.) Neither the name of Trilead nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.trilead.ssh2.compression;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Kenny Root
 *
 */
public class CompressionFactory {
	private CompressionFactory() { }

	private static class CompressorEntry
	{
		String type;
		String compressorClass;

		private CompressorEntry(String type, String compressorClass)
		{
			this.type = type;
			this.compressorClass = compressorClass;
		}
	}

	private static List<CompressorEntry> compressors = new ArrayList<>();

	static
	{
		/* Higher Priority First */
		compressors.add(new CompressorEntry("zlib", "com.trilead.ssh2.compression.Zlib"));
		compressors.add(new CompressorEntry("zlib@openssh.com", "com.trilead.ssh2.compression.ZlibOpenSSH"));
		compressors.add(new CompressorEntry("none", ""));
	}

	static void addCompressor(String protocolName, String className) {
		compressors.add(new CompressorEntry(protocolName, className));
	}

	public static String[] getDefaultCompressorList()
	{
		String[] list = new String[compressors.size()];
		for (int i = 0; i < compressors.size(); i++)
		{
			CompressorEntry ce = compressors.get(i);
			list[i] = ce.type;
		}
		return list;
	}

	public static void checkCompressorList(String[] compressorCandidates)
	{
		for (String compressorCandidate : compressorCandidates) {
			getEntry(compressorCandidate);
		}
	}

	public static ICompressor createCompressor(String type)
	{
		try
		{
			CompressorEntry ce = getEntry(type);
			if ("".equals(ce.compressorClass))
				return null;

			Class<?> cc = Class.forName(ce.compressorClass);
			Constructor<?> constructor = cc.getConstructor();
			return (ICompressor) constructor.newInstance();
		}
		catch (Exception e)
		{
			throw new IllegalArgumentException("Cannot instantiate " + type);
		}
	}

	private static CompressorEntry getEntry(String type)
	{
		for (CompressorEntry ce : compressors) {
			if (ce.type.equals(type))
				return ce;
		}
		throw new IllegalArgumentException("Unknown algorithm " + type);
	}
}
