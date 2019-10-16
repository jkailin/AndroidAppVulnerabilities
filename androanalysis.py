from androguard import misc
from androguard import session
import os, sys
import json
import requests

# Give the path to a folder with android apks
APK_FOLDER_PATH=""
TWEAK_URL="https://api.apptweak.com/android/applications/"

# app tweak analysis
application_package_analyze=["com.gamecircus.PrizeClaw", "air.com.generamobile.colormaniaguess"]

if __name__=="__main__":

	#calculate average target sdk
	#-------------------------------------------
	total_target_sdk_counter = 0

	for root, dirs, files in os.walk(APK_FOLDER_PATH):
		for f in files:
			if f.endswith(".apk"):
				path = APK_FOLDER_PATH + "/" + f
				print path
				a,d,dx = misc.AnalyzeAPK(path)
				target_sdk = a.get_effective_target_sdk_version()
				if target_sdk!= None:
					total_target_sdk_counter+=target_sdk
					print total_target_sdk_counter

	print "average target sdk:" + total_target_sdk_counter/50
	
	#-------------------------------------------

	# for application in application_package_analyze:
	# 	print application
	# 	headers = {'Apptweak-Key': ''}

	# 	req = requests.get(TWEAK_URL + application + ".json", headers=headers)
	# 	print req.json()