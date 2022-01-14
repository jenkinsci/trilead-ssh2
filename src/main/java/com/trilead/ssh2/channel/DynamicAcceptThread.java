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
	private final ChannelManager cm;
	private final ServerSocket ss;

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

	public InetSocketAddress getSocketAddress() {
		return new InetSocketAddress(ss.getInetAddress(), ss.getLocalPort());
	}

	class DynamicAcceptRunnable implements Runnable {
		private static final int idleTimeout = 0; //180000; //3 minutes

		private final Socket sock;
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

			final StreamForwarder r2l = new StreamForwarder(cn, null, sock, cn.getStdoutStream(), out, "RemoteToLocal");
			final StreamForwarder l2r = new StreamForwarder(cn, r2l, sock, in, cn.stdinStream, "LocalToRemote");

			r2l.setDaemon(true);
			l2r.setDaemon(true);
			r2l.start();
			l2r.start();
		}
	}
}
