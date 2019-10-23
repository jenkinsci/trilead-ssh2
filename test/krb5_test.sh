#!/usr/bin/env bash
#
# The script is used to provision a Kerberos environment an run some authentication tests againts it.
# it use the enviroment defined in https://github.com/criteo/kerberos-docker.git
# Author: Kuisathaverat
#

git clone https://github.com/criteo/kerberos-docker.git
cd kerberos-docker
make install
cd ..
docker cp . krb5-machine-instance-com:/root/trilead-ssh2
docker exec -it -w "/root/trilead-ssh2" -e "KRB5_HOST=krb5-service-instance-com" -e "KRB5_USER=bob" krb5-machine-instance-com mvn clean test -Dtest=KerberosTest