#!/bin/bash

# variables
#------------------------------------------------------------------------------------

# Path to APK files
# APK_PATH="/home/j/Desktop/randapk"

#Path to random smali files
# RANDOM_SMALI_PATH="/home/j/Desktop/randsmali"

#Path to smali files
# IOT_SMALI_PATH="/home/j/Desktop/iotsmali"


#Edit this path to the folder to be analyzed
#Path to smali files
SMALI_PATH="example/path"

initial=$(pwd)

#functions
#------------------------------------------------------------------------------------

SSl_vulnerability() {

a=true

#Search for pieces of code that likely mean it is insecure
#allows all hostnames
grep -E -m 1 -s -i "org.apache.http.conn.ssl.AllowAllHostnameVerifier|FakeHostnameVerifier|\
NaiveHostnameVerifier|AcceptAllHostnameVerifier|allow_all_hostname" $1 /dev/null | sed \
's/^/\nTrustManager allows all hostnames: \n/'

# Common TrustManager implementations that accept all certificates
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

export -f SSl_vulnerability

#------------------------------------------------------------------------------------

# go into folder with smali application folders
cd $SMALI_PATH

useGPS=false

main=$(pwd)

app_counter=0
GPSCounter=0
GPSUnusedCounter=0
RequestPermissionsCounter=0
eavesdropping=0
tracking=0
sms_spam=0
SSL_counter=0
chooser_counter=0
broadcast_counter=0
exported_counter=0

for d in * ; do

let "app_counter++"
echo $app_counter
echo $d

cd $main
cd $d

#get android manifest file
manifest=$(grep "manifest" AndroidManifest.xml)

#get package to find path to smali code
package_line=$(echo ${manifest} | grep -o 'package=".*"' | sed 's/"//g' | grep -o '^[^ ]*')
package_name=${package_line//package=/}
file_path=$(echo ${package_name} | tr . /)

#------------------------------------------------------------------------------------


#------------------------------------------------------------------------------------
useGPS=$(grep -q "ACCESS_COARSE_LOCATION|ACCESS_FINE_LOCATION" AndroidManifest.xml)

#GPS Usage
if grep -qE "ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|android.hardware.location.gps" AndroidManifest.xml;
then
#go into smali code directory
cd smali/${file_path}
echo "Asks for GPS Permissions"
let "GPSCounter++"
if ${useGPS};
 	then
		find . -type f -name '*.smali' ! -name '*$*' | grep -r -q -E -i -m1 --include=\*.smali "location|GPS" || let "GPSUnusedCounter++"
	fi
fi

#------------------------------------------------------------------------------------
#dangerous combinations

cd ${main}
cd $d
if grep -q -i "RECORD_AUDIO" AndroidManifest.xml && grep -q -l -i "INTERNET" AndroidManifest.xml;
	then
	echo "eavesdropping"
	let "eavesdropping++"
fi

if grep -q -i "ACCESS_FINE_LOCATION" AndroidManifest.xml && grep -q -l -i "RECEIVE_BOOT_COMPLETE" AndroidManifest.xml;
	then
	echo "tracking"
	let "tracking++"
fi

if grep -q -i "SEND_SMS" AndroidManifest.xml && grep -q -l -i "WRITE_SMS" AndroidManifest.xml;
	then
	echo "sms spam"
	let "sms_spam++"
fi

cd ${main}


# #------------------------------------------------------------------------------------
#SSL/interface vulnerabilities

cd ${main}
cd $d
cd smali/${file_path}

find . -type f -name '*.smali' ! -name '*$*' -exec bash -c 'SSl_vulnerability "{}"' \;



#------------------------------------------------------------------------------------

cd $main
cd $d


cd smali/${file_path}

#find . -type f -name '*.smali' ! -name '*$*' | grep -r -E -i -m1 --include=\*.smali "createchooser"
find . -type f -name '*.smali' ! -name '*$*' | grep -r -E -i -m1 --include=\*.smali "receiver" | grep "exported=false"



#------------------------------------------------------------------------------------

done

echo "----------------------------------"

echo "RESULTS"
echo "Asked for GPS permissions: "$GPSCounter
echo "Asked for GPS permissions but may not have requested location updates: "$GPSUnusedCounter

# echo "Requested Permissions outside of manifest: "$RequestPermissionsCounter

echo "Eavesdropping: "$eavesdropping
echo "Tracking: "$tracking
echo "SMS Spam: "$sms_spam
echo "exported: "$exported_counter

