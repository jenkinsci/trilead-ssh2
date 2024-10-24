
Trilead SSH-2 for Java - build 212
==================================

http://www.trilead.com

Trilead SSH-2 for Java is a library which implements the SSH-2 protocol in pure Java
(minimum required JRE: 1.4.2). It allows one to connect to SSH servers from within
Java programs. It supports SSH sessions (remote command execution and shell access),
local and remote port forwarding, local stream forwarding, X11 forwarding, SCP and SFTP.
There are no dependencies on any JCE provider, as all crypto functionality is included.

This distribution contains the source code, examples, javadoc and the FAQ.
It also includes a pre-compiled jar version of the library which is ready to use.

- Please read the included LICENCE.txt
- Latest changes can be found in HISTORY.txt

The latest version of the FAQ is available on the website.

Please feel free to contact us. We welcome feedback of any kind!
Contact: support@trilead.com or go to the public forum at http://www.trilead.com

Zurich, March 2008

## Algorithm filters

The algorithm filters can be used to restrict the algorithms that are used by the library.
The filters will remove the algorithms you specify from the SSH algorithms negotiation between client and server.
The library supports the following algorithm filters:
* Kex (Key Exchange) algorithm filter
* Host Key algorithm filter
* Encryption algorithm filter
* MAC algorithm filter

To filter algorithms enable the filters using the following System properties:


* com.trilead.ssh2.jenkins.FilterKexAlgorithms.enabled (default: true)
* com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.enabled (default: true)
* com.trilead.ssh2.jenkins.FilterMacAlgorithms.enabled (default: true)
* com.trilead.ssh2.jenkins.FilterEncrytionAlgorithms.enabled (default: true)

The algorithms are specified as a comma separated list of algorithm names.
To configure the algorithm filters, use the following System properties:

* com.trilead.ssh2.jenkins.FilterKexAlgorithms.algorithms
* com.trilead.ssh2.jenkins.FilterHostKeyAlgorithms.algorithms
* com.trilead.ssh2.jenkins.FilterMacAlgorithms.algorithms
* com.trilead.ssh2.jenkins.FilterEncrytionAlgorithms.algorithms

Example
```bash
java -Dcom.trilead.ssh2.jenkins.FilterKexAlgorithms.enabled=true \
    -Dcom.trilead.ssh2.jenkins.FilterKexAlgorithms.algorithms=diffie-hellman-group-exchange-sha256 \
    -jar jenkins.war
```

To check the algorithms filtered by the library, check the `Filter*` classes at the package [`com.trilead.ssh2.jenkins`](src/com/trilead/ssh2/jenkins).