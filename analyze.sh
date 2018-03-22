#!/bin/bash

#script can be run with
#$ ./analyze.sh

#get android manifest file
manifest=$(grep "manifest" AndroidManifest.xml)

#get package to find path to smali code
package_line=$(echo ${manifest} | grep -o 'package=".*"' | sed 's/"//g' | grep -o '^[^ ]*')
package_name=${package_line//package=/}
file_path=$(echo ${package_name} | tr . /)

#echo ${file_path}

#go into smali code directory
cd smali/${file_path}

#finds and prints out vulnerabilities in a file
search_vulnerability() {

#Search for pieces of code that likely mean it is insecure
#vulnerabilities that allow all hostnames
grep -E -m 1 -s -i "org.apache.http.conn.ssl.AllowAllHostnameVerifier|FakeHostnameVerifier|\
NaiveHostnameVerifier|AcceptAllHostnameVerifier|allow_all_hostname" $1 /dev/null | sed \
's/^/\nTrustManager allows all hostnames: \n/'

#Common TrustManager implementations that accept all certificates
grep -E -m 1 -s -i\
 "AcceptAllTrustM|AllTrustM|DummyTrustM|EasyX509TrustM|FakeTrustM|FakeX509TrustM|FullX509TrustM\
|NaiveTrustM|NonValidatingTrustM|NullTrustM|OpenTrustM|PermissiveX509TrustM|SimpleTrustM|SimpleX509TrustM|TrivialTrustM|\
TrustAllManager|TrustAllTrustM|TrustAnyCertTrustM|UnsafeX509TrustM|VoidTrustM"\
 $1 /dev/null | sed 's/^/\nTrust Manager accepts all certificates: \n/'

#Common SSL Factory implementations that accept all certificates
grep -E -m 1 -s -i\
 "AcceptAllSSLSocketF|AllTrustingSSLSocketF|AllTrustSSLSocketF|AllSSLSocketF|DummySSLSocketF\
 EasySSLSocketF|FakeSSLSocketF|InsecureSSLSocketF|NonValidatingSSLSocketF|NaiveSslSocketF|SimpleSSLSocketF\
 SSLSocketFUntrustedCert|SSLUntrustedSocketF|TrustAllSSLSocketF|TrustEveryoneSocketF|NaiveTrustManagerF|\
 LazySSLSocketF|UnsecureTrustManagerF"\
 $1 /dev/null | sed 's/^/\nSSL socket factory accepts all certificates: \n/'

#grep -E -m 1 -s "http://" $1 /dev/null | xargs grep -l "Norsk" | sed 's/^/\nnon SSL protected site: \n/'

grep -l -m 1 -i "http://" $1 | xargs grep -l -m 1 -i "loginactivity" $1 |\
xargs grep -l -m 1 -i "JSONObject" $1 | xargs grep -l -m 1 -i "url" $1 | xargs grep -l -m 1 -i "BroadcastReceiver" $1 |\
sed 's/^/\nhttp error in:\n /'

grep -E -m 1 -s -i "SslErrorHandler;->proceed()" $1 /dev/null | sed 's/^/\nSSL error ignored:\n /'

}

export -f search_vulnerability

echo "---------possible vulnerabilities found---------"

# find all smali code in the directories
find . -type f -name '*.smali' ! -name '*$*' -exec bash -c 'search_vulnerability "{}"' \;