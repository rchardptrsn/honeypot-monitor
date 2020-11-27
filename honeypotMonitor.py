#!/usr/bin/env python
"""
Credit: https://gist.github.com/omnidan/1456674
Copyright (c) 2011, Daniel Bugl
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Daniel Bugl.
4. Neither the name of Daniel Bugl nor the names
   of its other contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY Daniel Bugl ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

# Import packages
import time
import socket
import logging
import os
import json
import ipinfo
from opencensus.ext.azure.log_exporter import AzureLogHandler


# function to initialize App Insights logger object
def startLogger():
	# Get Azure Monitor instrumentation key from environment variable
	instrumentation_key = os.environ.get('InstrumentationKey')

	# initialize logger object
	logger = logging.getLogger(__name__)

	# define connection string attribute of logger object
	# this uses our Azure Monitor instrumentation key
	logger.addHandler(AzureLogHandler(
		# connection_string='InstrumentationKey=fd8638b6-ccd6-41f0-a273-e8b15726c4dd'
		connection_string='InstrumentationKey=fd8638b6-ccd6-41f0-a273-e8b15726c4dd'
	))

	return logger


# Write connection attempts to App Insights
# https://docs.microsoft.com/en-us/azure/azure-monitor/app/opencensus-python
def writeAppInsights(logger,address,data):

	# create the custom_dimensions dictionary
	logData = {'custom_dimensions': {

		'Time': time.ctime(),
		'IP': address[0],
		'Port': address[1],
		'City': data.city,
		'Country': data.country,
		'CountryName': data.country_name,
		'Location': data.loc,
		'Region': data.region,
		'Timezone': data.timezone,
		'Details': json.dumps(data.all)
		}
	}
	# pass your custom dimensions to extra
	# send data to app insights as an action
	logger.warning('action',extra=logData)


def ipData(address):
	# https://stackoverflow.com/questions/24678308/how-to-find-location-with-ip-address-in-python
	ip_address = address[0]

	# ipinfo package - free up to 50k requests
	# https://github.com/ipinfo/python
	# login to ipinfo account: https://ipinfo.io/account?welcome=true
	access_token = 'a6e213eb2f8834'
	# initialize handler with access token
	handler = ipinfo.getHandler(access_token)
	# create details object from handler search of the ip address
	details = handler.getDetails(ip_address)

	return details


def writeLog(client, data=''):
	separator = '='*50
	fopen = open('./honey.mmh', 'a')
	fopen.write('Time: {}\nIP: {}\nPort: {}\nData: {}\n{}\n\n'.format(time.ctime(), client[0], client[1], data, separator))
	fopen.close()


###############################################################
def main(host, port):
	print ('Starting honeypot!')
	# initialize Azure Monitoring logger object
	logger = startLogger()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((host, port))
	s.listen(100)
	while True:
		(insock, address) = s.accept()
		data = ipData(address)
		print ('Connection from:{}:{}'.format(address[0], address[1]))
		try:
			# python 2.7 code commented out: insock.send('{}\n'.format(motd))
			conndata = insock.recv(1024)
			insock.close()
		except socket.error as e:
			writeAppInsights(logger, address, data)
			#writeLog(address)
		else:
			#writeLog(address, conndata)
			writeAppInsights(logger, address, data)

        
if __name__=='__main__':
	try:
		host = '10.0.0.4'
		port = 1025
		main(host, port)
	except KeyboardInterrupt:
		print('Bye!')
		# Create an Azure Monitoring logger object
		logger = startLogger()
		# Call the 'warning' method of the logger object with custom dimensions.
		logger.warning('error',extra={'custom_dimensions':{'error':'KeyboardInterrupt', 'Time':time.ctime()}})
		exit(0)
	except BaseException as e:
		hp_error = 'Error: {}'.format(e)
		print(hp_error)
		# Create an Azure Monitoring logger object
		logger = startLogger()
		# Call the 'warning' method of the logger object with custom dimensions.
		logger.warning('error',extra={'custom_dimensions':{'error':hp_error, 'Time':time.ctime()}})
		exit(1)
