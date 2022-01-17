/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.trilead.ssh2.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.Socket;

import com.trilead.ssh2.log.Logger;

import net.sourceforge.jsocks.Proxy;
import net.sourceforge.jsocks.ProxyMessage;
import net.sourceforge.jsocks.Socks5Message;
import net.sourceforge.jsocks.SocksException;
import net.sourceforge.jsocks.server.ServerAuthenticator;
import net.sourceforge.jsocks.server.ServerAuthenticatorNone;


/**
 * DynamicAcceptThread.
 * 
 * @author Kenny Root
 * @version $Id$
 */
public class DynamicAcceptThread extends Thread
		implements IChannelWorkerThread {
	
	private static final Logger log = Logger.getLogger(DynamicAcceptThread.class);
	
	private final ChannelManager cm;
	private final ServerSocket ss;

	public DynamicAcceptThread(ChannelManager cm, InetSocketAddress localAddress)
			throws IOException {
		this.cm = cm;

		setName("DynamicAcceptThread");
				
		ss = new ServerSocket();
		ss.bind(localAddress);
	}

	public DynamicAcceptThread(ChannelManager cm, int local_port)
			throws IOException {
		this.cm = cm;

		setName("DynamicAcceptThread");

		ss = new ServerSocket(local_port);
	}

	public InetSocketAddress getSocketAddress() {
		return new InetSocketAddress(ss.getInetAddress(), ss.getLocalPort());
	}

	@Override
	public void run() {
		try {
			cm.registerThread(this);
		} catch (IOException e) {
			stopWorking();
			return;
		}

		while (true) {
			Socket sock;

			try {
				sock = ss.accept();
			} catch (IOException e) {
				stopWorking();
				return;
			}

			DynamicAcceptRunnable dar = new DynamicAcceptRunnable(
				new ServerAuthenticatorNone(), sock);
			Thread t = new Thread(dar);
			t.setDaemon(true);
			t.start();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.trilead.ssh2.channel.IChannelWorkerThread#stopWorking()
	 */
	@Override
	public void stopWorking() {
		try {
			/* This will lead to an IOException in the ss.accept() call */
			ss.close();
		} catch (IOException ignored) {
		}
	}
	
	class DynamicAcceptRunnable implements Runnable {
		private static final int idleTimeout = 0;//60*1000*6; // 6 minutes

		private ServerAuthenticator auth;
		private final Socket sock;
		private InputStream in;
		private OutputStream out;

		public DynamicAcceptRunnable(ServerAuthenticator auth, Socket sock) {
			this.auth = auth;
			this.sock = sock;

			setName("DynamicAcceptRunnable");
		}
		
		@Override
		public void run() {
			try {
				startSession();
			} catch (IOException ioe) {
				int error_code = Proxy.SOCKS_FAILURE;

				if (ioe instanceof SocksException)
					error_code = ((SocksException) ioe).errCode;
				else if (ioe instanceof NoRouteToHostException)
					error_code = Proxy.SOCKS_HOST_UNREACHABLE;
				else if (ioe instanceof ConnectException)
					error_code = Proxy.SOCKS_CONNECTION_REFUSED;
				else if (ioe instanceof InterruptedIOException)
					error_code = Proxy.SOCKS_TTL_EXPIRE;

				if (error_code > Proxy.SOCKS_ADDR_NOT_SUPPORTED
					|| error_code < 0) {
					error_code = Proxy.SOCKS_FAILURE;
				}

				sendErrorMessage(error_code);
			} catch (Error e) {
				// Force to GC here
				System.gc();
			} finally {
				if (auth != null)
					auth.endSession();
			}
		}

		private void handleRequest(ProxyMessage msg) throws IOException {
			if (!auth.checkRequest(msg))
				throw new SocksException(Proxy.SOCKS_FAILURE);

			if (msg.command == Proxy.SOCKS_CMD_CONNECT) {
				onConnect(msg);
			} else {
				throw new SocksException(Proxy.SOCKS_CMD_NOT_SUPPORTED);
			}
		}

		private void onConnect(ProxyMessage msg) throws IOException {
			ProxyMessage response = new Socks5Message(Proxy.SOCKS_SUCCESS,
				(InetAddress) null, 0);
			
			response.write(out);

			String destHost = msg.host;
			if (msg.ip != null)
				destHost = msg.ip.getHostAddress();

			try {
				/*
				 * This may fail, e.g., if the remote port is closed (in
				 * optimistic terms: not open yet)
				 */

				Channel cn = cm.openDirectTCPIPChannel(destHost, msg.port, "127.0.0.1",
					0);

				try {
					StreamForwarder r2l = new StreamForwarder(cn, null, null, cn.getStdoutStream(), out,
							"RemoteToLocal");
					StreamForwarder l2r = new StreamForwarder(cn, r2l, sock, in, cn.stdinStream,
							"LocalToRemote");

					r2l.setDaemon(true);
					l2r.setDaemon(true);
					r2l.start();
					l2r.start();
				} catch (IOException e) {
					try {
						/*
						 * This message is only visible during debugging, since we
						 * discard the channel immediatelly
						 */
						cn.cm.closeChannel(cn,
								"Weird error during creation of StreamForwarder ("
										+ e.getMessage() + ")", true);
					} catch (IOException ignore) {
					}
				}

			} catch (IOException e) {
				/*
				 * Simply close the local socket and wait for the next incoming
				 * connection
				 */

				try {
					sock.close();
				} catch (IOException ignore) {
				}
			}
		}

		private ProxyMessage readMsg(InputStream in) throws IOException {
			PushbackInputStream push_in;
			if (in instanceof PushbackInputStream)
				push_in = (PushbackInputStream) in;
			else
				push_in = new PushbackInputStream(in);

			int version = push_in.read();
			push_in.unread(version);

			ProxyMessage msg;

			if (version == 5) {
				msg = new Socks5Message(push_in, false);
			} else {
				throw new SocksException(Proxy.SOCKS_FAILURE);
			}
			return msg;
		}

		private void sendErrorMessage(int error_code) {
			 ProxyMessage err_msg = new Socks5Message(error_code);
			
			try {
				err_msg.write(out);
			} catch (IOException ignored) {
			}
		}

		private void startSession() throws IOException {
			sock.setSoTimeout(idleTimeout);

			try {
				auth = auth.startSession(sock);
			} catch (IOException ioe) {
				log.log(50, "Could not start SOCKS session");
				ioe.printStackTrace();
				auth = null;
				return;
			}

			if (auth == null) { // Authentication failed
				log.log(50, "SOCKS auth failed");
				return;
			}

			in = auth.getInputStream();
			out = auth.getOutputStream();

			ProxyMessage msg = readMsg(in);
			handleRequest(msg);
		}
	}
}

