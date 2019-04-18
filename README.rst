Quick start
===========

Install prerequisites::

  $ sudo apt-get install protobuf-c-compiler python

Build::

  $ mkdir build
  $ cd build
  $ cmake ../
  $ make

Example client run::

  $ eeconnect -s 123454321 -e SecretSkin -c ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA

Client usage::

  usage: eeconnect [--version] [--build] [--embedded] [-D] [-N] [-c CIPHER_LIST]
                   [-e ENGINE] [-r RECONNECT] [-s SERIAL_NUMBER] [-t RETRY]
                   [--conn-timeout=TIME] [--ping-interval=TIME] [--ping-timeout=TIME]
                   [--ssl-negotiation-maxtime=TIME]

  optional arguments:
   --version             display EEConnect version information
   --build               display EEConnect build options
   --embedded            display EEConnect embedded files content
   -D                    enable daemon mode
   -N                    disable SSL encryption
   -c CIPHER_LIST        openSSL cipher list which can be used for encryption:
                         cipher1:cihper2:cipher3: ... :cipherN
   -e ENGINE             openSSL engine name which will be used
   -r RECONNECT          define reconnect wait time (in seconds)
   -s SERIAL_NUMBER      define serial number for this client
   -t RETRY              define retry wait time (in seconds)
   --ssl-negotiation-maxtime=TIME maximum time in seconds to wait for SSL negotiation
   --conn-timeout=TIME   maximal time of waiting for peer connection accept
   --ping-interval=TIME  sending ping messages interval
   --ping-timeout=TIME   maximal time of waiting for peer's ping

Example server run::

  $ eeserver -p 50051

Server usage::

  usage: eeserver [-N] [-p PORT] [--ping-interval=TIME]
                       [--ping-timeout=TIME]

  optional arguments:
   -N                    disable SSL encryption
   -p PORT               set server port
   --ping-interval=TIME  sending ping messages interval
   --ping-timeout=TIME   maximal time of waiting for peer's ping

Example certificate preparation
===============================

Below you can find example certificate generation using `easy-rsa`_ tool::

  [tmp]$ cd eeconnect
  [eeconnect]$ cp -r /etc/easy-rsa/ ./
  [eeconnect]$ cd easy-rsa/
  [easy-rsa]$ easyrsa init-pki

  init-pki complete; you may now create a CA or requests.
  Your newly created PKI dir is: /tmp/eeconnect/easy-rsa/pki

  [easy-rsa]$ easyrsa build-ca nopass

  Using SSL: openssl OpenSSL 1.1.1b  26 Feb 2019
  Generating RSA private key, 2048 bit long modulus (2 primes)
  .........................................+++++
  ............+++++
  e is 65537 (0x010001)
  Can't load /tmp/eeconnect/easy-rsa/pki/.rnd into RNG
  140015632192000:error:2406F079:random number generator:RAND_load_file:Cannot open file:crypto/rand/randfile.c:98:Filename=/tmp/eeconnect/easy-rsa/pki/.rnd
  You are about to be asked to enter information that will be incorporated
  into your certificate request.
  What you are about to enter is what is called a Distinguished Name or a DN.
  There are quite a few fields but you can leave some blank
  For some fields there will be a default value,
  If you enter '.', the field will be left blank.
  -----
  Common Name (eg: your user, host, or server name) [Easy-RSA CA]:

  CA creation complete and you may now import and sign cert requests.
  Your new CA certificate file for publishing is at:
  /tmp/eeconnect/easy-rsa/pki/ca.crt

  [easy-rsa]$ easyrsa build-server-full servername nopass

  Using SSL: openssl OpenSSL 1.1.1b  26 Feb 2019
  Generating a RSA private key
  .....+++++
  ......+++++
  writing new private key to '/tmp/eeconnect/easy-rsa/pki/private/servername.key.tzw3EF9pmY'
  -----
  Using configuration from /tmp/eeconnect/easy-rsa/pki/safessl-easyrsa.cnf
  Check that the request matches the signature
  Signature ok
  The Subject's Distinguished Name is as follows
  commonName            :ASN.1 12:'servername'
    Certificate is to be certified until Mar 12 09:08:50 2022 GMT (1080 days)

  Write out database with 1 new entries
  Data Base Updated
  [easy-rsa]$ easyrsa build-client-full clientname nopass

  Using SSL: openssl OpenSSL 1.1.1b  26 Feb 2019
  Generating a RSA private key
  ..............................................+++++
  ...................................................+++++
  writing new private key to '/tmp/eeconnect/easy-rsa/pki/private/clientname.key.mji4KQ8uxs'
  -----
  Using configuration from /tmp/eeconnect/easy-rsa/pki/safessl-easyrsa.cnf
  Check that the request matches the signature
  Signature ok
  The Subject's Distinguished Name is as follows
  commonName            :ASN.1 12:'clientname'
  Certificate is to be certified until Mar 12 09:09:12 2022 GMT (1080 days)

  Write out database with 1 new entries
  Data Base Updated
  [easy-rsa]$ cd ..
  [eeconnect]$ ln -sf ../easy-rsa/pki/private/servername.key server_confs/server.key
  [eeconnect]$ ln -sf ../easy-rsa/pki/private/clientname.key client_confs/client.key
  [eeconnect]$ ln -sf ../easy-rsa/pki/issued/servername.crt server_confs/server.cert
  [eeconnect]$ ln -sf ../easy-rsa/pki/issued/clientname.crt client_confs/client.cert
  [eeconnect]$ ln -sf ../easy-rsa/pki/ca.crt client_confs/ca.cert

.. _`easy-rsa`: https://github.com/OpenVPN/easy-rsa


Security
===========

The security of our products and services is top priority for us – so we naturally respect and appreciate the work of security experts in this area. You can also help us by identifying vulnerabilities so we can address them.

If you discover a vulnerability, please contact us at report-vulnerabilities@een.com

Notes on how to report vulnerabilities
---------------------------------------

* Please write your correspondence in English or Dutch, if possible.
* Please provide your name and contact information.
* So that we can understand your report quickly and efficiently, please include a proof of concept and a detailed description, if possible.
* Please give us time to develop and roll out countermeasures, before you make technical details public (Responsible Disclosure).
* Common vulnerabilites are excluded:
    * Attacks based on “social engineering” by employees or dealers
    * Phishing attempts
    * Denial-of-service attacks on servers and websites
    * Non-reproducible vulnerabilities
    * Sabotage of mechanical parts of cameras or bridges

We will try to respond to your message and provide you with feedback within two to three business days. 

Recognition of security experts
-------------------------------

We wish to thank and acknowledge the security experts who are the first to identify vulnerabilities. Thanks to their support and the countermeasures developed by us, we continue to enhance the security of our products and services.
