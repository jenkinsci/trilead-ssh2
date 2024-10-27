FROM ubuntu:22.04

# This Docker image is build and push to the repository it takes about 6 min to build
# The reason to pre-build it is because it compiles five libraries and an application everytime we run the test
#  docker build -t ghcr.io/jenkinsci/trilead-ssh2:netopeer-3.5.1 .


# defaults
RUN \
	apt-get update && apt-get install -y \
	net-tools \
	git \
	wget \
	libssl-dev \
	libtool \
	build-essential \
	vim \
      autogen \
	autoconf \
	automake \
	pkg-config \
	libgtk-3-dev \
	make \
	vim \
	valgrind \
	doxygen \
	libev-dev \
	libpcre3-dev \
	unzip \
	sudo \
	python3 \
	build-essential \
	bison \
	flex \
	swig \
	libcmocka0 \
	libcmocka-dev \
	cmake \
      gcc \
      libpsl-dev \ 
	supervisor \
      libpam0g-dev \
      && rm -rf /var/lib/apt/lists/*

      

# Adding netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo


# Clearing and setting authorized ssh keys
RUN \
	echo '' > /home/netconf/.ssh/authorized_keys && \
	ssh-keygen -A && \
	ssh-keygen -t rsa -b 4096 -P '' -f /home/netconf/.ssh/id_rsa && \
	cat /home/netconf/.ssh/id_rsa.pub >> /home/netconf/.ssh/authorized_keys


# Updating shell to bash
RUN sed -i s#/home/netconf:/bin/false#/home/netconf:/bin/bash# /etc/passwd

RUN mkdir /opt/dev && sudo chown -R netconf /opt/dev

# set password for user (same as the username)
RUN echo "root:root" | chpasswd

# libyang
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/libyang.git && \
      cd libyang && git checkout tags/v3.4.2 && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# sysrepo
RUN \
      cd /opt/dev && \
      git clone https://github.com/sysrepo/sysrepo.git && \
      cd sysrepo && git checkout tags/v2.11.7 && mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="Release" .. && \
      make -j2 && \
      make install && \
      ldconfig

#libssh (for libnetconf2)
RUN \
      cd /opt/dev && \
      git clone http://git.libssh.org/projects/libssh.git && cd libssh && git checkout tags/libssh-0.11.1  &&\
      mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="Release" -DWITH_ZLIB=ON -DWITH_NACL=OFF -DWITH_PCAP=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

#curl (for libnetconf2)

RUN \
cd /opt/dev && \
git clone https://github.com/curl/curl.git && cd curl && git checkout tags/curl-8_9_1 &&\
autoreconf -fi && \
./configure --prefix=/usr --with-openssl && \
make -j2 && \
make install && \
ldconfig


# libnetconf2
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/libnetconf2.git && \
      cd libnetconf2 && git checkout tags/v3.5.1 && mkdir build && cd build && \
      cmake  -DCMAKE_FIND_PACKAGE_NO_SYSTEM_PATH=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_TESTS=OFF .. &&\
      make -j2 && \
      make install && \
      ldconfig


# netopeer2
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/Netopeer2.git && cd Netopeer2 && \
      git checkout tags/v2.2.31 && \
      mkdir build && cd build && \
      cmake -DNACM_RECOVERY_UID=102 -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && \
      make -j2 && \
      make install

      RUN rm -fr /opt/dev
      ENV EDITOR vim
      EXPOSE 830 
      EXPOSE 4334

# start netopeer2 server.
CMD ["/usr/sbin/netopeer2-server", "-d", "-v2 3"]
      
#Comment above and uncomment below if you want to debug SSH specifc actions on Netopeer2 when running.
#CMD ["/usr/sbin/netopeer2-server", "-d", "-c", "SSH"]
     