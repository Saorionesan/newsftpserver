# sftpserver

SFTP Server (SSH File Transfer Protocol) based on `Apache MINA SSHD`. Open Source Java project under Apache License v2.0

### Current Stable Version is [1.2.3](https://maven-release.s3.amazonaws.com/release/org/javastack/sftpserver/1.2.3/sftpserver-1.2.3-bin.zip)

---

### Versions

| sftpserver | Java |
| :--------- | :--- |
| 1.0.x      | 1.6+ |
| 1.1.x      | 1.6+ |
| 1.2.x      | 1.7+ |

## Config:

###### `${sftp.home}/conf/[id]/sftpd.properties` (all in one file)

	#
	## Global Options
	#
	# Listen on TCP port 22222
	sftpserver.global.port=22222
	# Enable compression (requires jzlib) (default: false)
	sftpserver.global.compress=true
	# Enable dummy shell (default: false)
	sftpserver.global.dummyshell=true
	#
	## Configure user "test"
	#
	# Password for user (unencrypted-plain-text)
	#sftpserver.user.test.userpassword=changeit
	# Password for user (encrypted)
	sftpserver.user.test.userpassword=$1$156RlTZJ$76bzjtXvDfgvouurtgEI10
	# PublicKeys for user (OpenSSH format)
	sftpserver.user.test.userkey.1=ssh-rsa AAAAB3NzaC1yc2EAAAADA...E7uQ==
	sftpserver.user.test.userkey.2=ssh-dss AAAAB3NzaC1kc3MAAACBA...IwtA==
	# Set user home directory (chrooted)
	sftpserver.user.test.homedirectory=./home/test/
	# Enable user (default: false)
	sftpserver.user.test.enableflag=true
	# Enable write (default: false)
	sftpserver.user.test.writepermission=true
	#

###### `${sftp.home}/conf/[id]/sftpd.properties` + `${sftp.home}/conf/[id]/htpasswd`

	#
	## Global Options
	#
	# Listen on TCP port 22222
	sftpserver.global.port=22222
	# Enable compression (requires jzlib) (default: false)
	sftpserver.global.compress=true
	# Enable dummy shell (default: false)
	sftpserver.global.dummyshell=true
	#
	## Configure htpasswd
	#
	# Enable htpasswd (default: false)
	sftpserver.htpasswd.enableflag=true
	# Set home directory for all users (chrooted)
	sftpserver.htpasswd.homedirectory=./home/test/
	# Enable write (default: false)
	sftpserver.htpasswd.writepermission=true
	#

---

## Running (Linux)

    ./bin/sftpd.sh <run|start|stop|restart|status> [id]

## Upstart Script (Linux)

    ./bin/sftpd.conf (you can copy to /etc/init/)

## Generate Encrypted Password (Linux)

    ./bin/sftpd.sh <pwd>

---

# DONEs

* Use Java SecurityManager/Policy File
* Non operating system accounts
* Homes are chrooted
* ReadOnly accounts
* Encrypted Passwords (SHA2/MD5/APR1)
* PublicKey Authenticator (OpenSSH keys RSA/DSA)
* Support [htpasswd file](https://httpd.apache.org/docs/2.2/misc/password_encryptions.html) (APR1) 

## MISC
Current hardcoded values:

* Hostkeys are writed to: `hostkey.pem` or `hostkey.ser` in `${sftp.home}/keys/` directory
* SecurityManager/Policy File is in `conf/${ID}/sftpd.policy` (custom) or `lib/sftpd.policy` (generic)
* Htpasswd File is in `conf/${ID}/htpasswd` (custom) or `conf/htpasswd` (generic)
* Only SHA2-512, SHA2-256 and SHA1-160 are enabled for HMAC (MD5, MD5-96, SHA1-96 are disabled)

---

Maven Dependencies:

[Apache MINA SSHD](http://mina.apache.org/sshd-project/)

* mina-core-`XXX`.jar
* sshd-core-`XXX`.jar

[Apache Commons Codec (password encryption)](http://commons.apache.org/codec/)

* commons-codec-`XXX`.jar

[Log4J (logging)](http://logging.apache.org/log4j/1.2/)

* log4j-`XXX`.jar

[SLF4J (logging)](http://www.slf4j.org/)

* slf4j-api-`XXX`.jar
* slf4j-log4j12-`XXX`.jar

[Bouncy Castle (encryption)](http://www.bouncycastle.org/java.html)

* bcprov-jdk15on-`XXX`.jar
* bcpkix-jdk15on-`XXX`.jar

[JZlib (for compression)](http://www.jcraft.com/jzlib/)

* jzlib-`XXX`.jar

---
Inspired in [mina-sshd](https://github.com/apache/mina-sshd/blob/master/sshd-core/src/main/java/org/apache/sshd/server/SshServer.java) and [openssh](http://www.openssh.org/).
