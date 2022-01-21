
package com.trilead.ssh2;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.transport.ClientServerHello;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * A <code>HTTPProxyData</code> object is used to specify the needed connection data
 * to connect through a HTTP proxy.
 *
 * @see Connection#setProxyData(ProxyData)
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: HTTPProxyData.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */

public class HTTPProxyData implements ProxyData
{
	private final String proxyHost;
	private final int proxyPort;
	private final String proxyUser;
	private final String proxyPass;
	private final String[] requestHeaderLines;
	//private Socket sock;

	/**
	 * Same as calling {@link #HTTPProxyData(String, int, String, String) HTTPProxyData(proxyHost, proxyPort, <code>null</code>, <code>null</code>)}
	 *
	 * @param proxyHost Proxy hostname.
	 * @param proxyPort Proxy port.
	 */
	public HTTPProxyData(String proxyHost, int proxyPort)
	{
		this(proxyHost, proxyPort, null, null);
	}

	/**
	 * Same as calling {@link #HTTPProxyData(String, int, String, String, String[]) HTTPProxyData(proxyHost, proxyPort, <code>null</code>, <code>null</code>, <code>null</code>)}
	 *
	 * @param proxyHost Proxy hostname.
	 * @param proxyPort Proxy port.
	 * @param proxyUser Username for basic authentication (<code>null</code> if no authentication is needed).
	 * @param proxyPass Password for basic authentication (<code>null</code> if no authentication is needed).
	 */
	public HTTPProxyData(String proxyHost, int proxyPort, String proxyUser, String proxyPass)
	{
		this(proxyHost, proxyPort, proxyUser, proxyPass, null);
	}

	/**
	 * Connection data for a HTTP proxy. It is possible to specify a username and password
	 * if the proxy requires basic authentication. Also, additional request header lines can
	 * be specified (e.g., "User-Agent: CERN-LineMode/2.15 libwww/2.17b3").
	 * <p>
	 * Please note: if you want to use basic authentication, then both <code>proxyUser</code>
	 * and <code>proxyPass</code> must be non-null.
	 * <p>
	 * Here is an example:
	 * <p>
	 * <code>
	 * new HTTPProxyData("192.168.1.1", "3128", "proxyuser", "secret", new String[] {"User-Agent: TrileadBasedClient/1.0", "X-My-Proxy-Option: something"});
	 * </code>
	 *
	 * @param proxyHost Proxy hostname.
	 * @param proxyPort Proxy port.
	 * @param proxyUser Username for basic authentication (<code>null</code> if no authentication is needed).
	 * @param proxyPass Password for basic authentication (<code>null</code> if no authentication is needed).
	 * @param requestHeaderLines An array with additional request header lines (without end-of-line markers)
	 *        that have to be sent to the server. May be <code>null</code>.
	 */

	public HTTPProxyData(String proxyHost, int proxyPort, String proxyUser, String proxyPass,
                         String[] requestHeaderLines)
	{
		if (proxyHost == null)
			throw new IllegalArgumentException("proxyHost must be non-null");

		if (proxyPort < 0)
			throw new IllegalArgumentException("proxyPort must be non-negative");

		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.proxyUser = proxyUser;
		this.proxyPass = proxyPass;
		this.requestHeaderLines = requestHeaderLines;
	}

	@Override
	public Socket openConnection(Socket sock, String hostname, int port, int connectTimeout, int readTimeout) throws IOException {
		InetAddress addr = InetAddress.getByName(proxyHost);
		sock.connect(new InetSocketAddress(addr, proxyPort), connectTimeout);
		sock.setSoTimeout(readTimeout);

			/* OK, now tell the proxy where we actually want to connect to */

		StringBuffer sb = new StringBuffer();

		sb.append("CONNECT ");
		sb.append(hostname);
		sb.append(':');
		sb.append(port);
		sb.append(" HTTP/1.0\r\n");

		if ((proxyUser != null) && (proxyPass != null))
		{
			String credentials = proxyUser + ":" + proxyPass;
			char[] encoded;
			try {
				encoded = Base64.encode(credentials.getBytes("ISO-8859-1"));
			} catch (UnsupportedEncodingException e) {
				encoded = Base64.encode(credentials.getBytes());
			}
			sb.append("Proxy-Authorization: Basic ");
			sb.append(encoded);
			sb.append("\r\n");
		}

		if (requestHeaderLines != null)
		{
			for (int i = 0; i < requestHeaderLines.length; i++)
			{
				if (requestHeaderLines[i] != null)
				{
					sb.append(requestHeaderLines[i]);
					sb.append("\r\n");
				}
			}
		}

		sb.append("\r\n");

		OutputStream out = sock.getOutputStream();

		try {
			out.write(sb.toString().getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			out.write(sb.toString().getBytes());
		}
		out.flush();

			/* Now parse the HTTP response */

		byte[] buffer = new byte[1024];
		InputStream in = sock.getInputStream();

		int len = ClientServerHello.readLineRN(in, buffer);

		String httpReponse;
		try {
			httpReponse = new String(buffer, 0, len, "ISO-8859-1");
		} catch (UnsupportedEncodingException e) {
			httpReponse = new String(buffer, 0, len);
		}

		if (!httpReponse.startsWith("HTTP/"))
			throw new IOException("The proxy did not send back a valid HTTP response.");

			/* "HTTP/1.X XYZ X" => 14 characters minimum */

		if ((httpReponse.length() < 14) || (httpReponse.charAt(8) != ' ') || (httpReponse.charAt(12) != ' '))
			throw new IOException("The proxy did not send back a valid HTTP response.");

		int errorCode = 0;

		try
		{
			errorCode = Integer.parseInt(httpReponse.substring(9, 12));
		}
		catch (NumberFormatException ignore)
		{
			throw new IOException("The proxy did not send back a valid HTTP response.");
		}

		if ((errorCode < 0) || (errorCode > 999))
			throw new IOException("The proxy did not send back a valid HTTP response.");

		if (errorCode != 200)
		{
			throw new HTTPProxyException(httpReponse.substring(13), errorCode);
		}

			/* OK, read until empty line */

		while (true)
		{
			len = ClientServerHello.readLineRN(in, buffer);
			if (len == 0)
				break;
		}

		return sock;
	}

	/*@Override
	public void close() {
		try {
			if (sock != null) {
				sock.close();
			}
		} catch (IOException ignored) {
		}
	}*/
}
