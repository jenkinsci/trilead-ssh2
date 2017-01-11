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

import org.connectbot.simplesocks.Socks5Server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * DynamicAcceptThread.
 *
 * @author Kenny Root
 * @version $Id$
 */
public class DynamicAcceptThread extends Thread implements IChannelWorkerThread {
	private ChannelManager cm;
	private ServerSocket ss;

	class DynamicAcceptRunnable implements Runnable {
		private static final int idleTimeout	= 180000; //3 minutes

		private Socket sock;
		private InputStream in;
		private OutputStream out;

		public DynamicAcceptRunnable(Socket sock) {
			this.sock = sock;

			setName("DynamicAcceptRunnable");
		}

		public void run() {
			try {
				startSession();
			} catch (IOException ioe) {
				try {
					sock.close();
				} catch (IOException ignore) {
				}
			}
		}

		private void startSession() throws IOException {
			sock.setSoTimeout(idleTimeout);

			in = sock.getInputStream();
			out = sock.getOutputStream();
			Socks5Server server = new Socks5Server(in, out);
			try {
				if (!server.acceptAuthentication() || !server.readRequest()) {
					System.out.println("Could not start SOCKS session");
					return;
				}
			} catch (IOException ioe) {
				server.sendReply(Socks5Server.ResponseCode.GENERAL_FAILURE);
				return;
			}

			if (server.getCommand() == Socks5Server.Command.CONNECT) {
				onConnect(server);
			} else {
				server.sendReply(Socks5Server.ResponseCode.COMMAND_NOT_SUPPORTED);
			}
		}

		private void onConnect(Socks5Server server) throws IOException {
			final Channel cn;

			String destHost = server.getHostName();
			if (destHost == null) {
				destHost = server.getAddress().getHostAddress();
			}

			try {
				/*
				 * This may fail, e.g., if the remote port is closed (in
				 * optimistic terms: not open yet)
				 */

				cn = cm.openDirectTCPIPChannel(destHost, server.getPort(),
						"127.0.0.1", 0);

			} catch (IOException e) {
				/*
				 * Try to send a notification back to the client and then close the socket.
				 */
				try {
					server.sendReply(Socks5Server.ResponseCode.GENERAL_FAILURE);
				} catch (IOException ignore) {
				}

				try {
					sock.close();
				} catch (IOException ignore) {
				}

				return;
			}

			server.sendReply(Socks5Server.ResponseCode.SUCCESS);

			final StreamForwarder r2l;
			final StreamForwarder l2r;
			try {
				r2l = new StreamForwarder(cn, null, sock, cn.stdoutStream, out, "RemoteToLocal");
				l2r = new StreamForwarder(cn, r2l, sock, in, cn.stdinStream, "LocalToRemote");
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

				return;
			}

			r2l.setDaemon(true);
			l2r.setDaemon(true);
			r2l.start();
			l2r.start();
		}
	}

	public DynamicAcceptThread(ChannelManager cm, int local_port)
			throws IOException {
		this.cm = cm;

		setName("DynamicAcceptThread");

		ss = new ServerSocket(local_port);
	}

	public DynamicAcceptThread(ChannelManager cm, InetSocketAddress localAddress)
			throws IOException {
		this.cm = cm;

		ss = new ServerSocket();
		ss.bind(localAddress);
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
			final Socket sock;
			try {
				sock = ss.accept();
			} catch (IOException e) {
				stopWorking();
				return;
			}

			DynamicAcceptRunnable dar = new DynamicAcceptRunnable(sock);
			Thread t = new Thread(dar);
			t.setDaemon(true);
			t.start();
		}
	}

	@Override
	public void stopWorking() {
		try {
			/* This will lead to an IOException in the ss.accept() call */
			ss.close();
		} catch (IOException ignore) {
		}
	}
}