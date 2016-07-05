# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import requests
import connexion
import logging
import re

from OpenSSL import crypto
from base64 import b64decode
#import boto3 # AWS SDK - https://boto3.readthedocs.io/en/latest/

# log files to be added...
logger = logging.getLogger( __name__)


'''
One fonction per message type. Currently there are 3:
- Notification
- SubscriptionConfirmation
- unsubscribeConfirmation
The first one will receive all autoscaling group notifications and will have to handle devices' behavior.
Values are checked by swagger still the _UnknownMessageType() will be called if no match.
'''
def _Notification( snsMessage):
	return connexion.problem( 404, "Notification error", "Don't be so hasty!")

'''
'''
def _UnsubscribeConfirmation( snsMessage):
	return connexion.problem( 404, "Unsubscribe error", "Don't be so hasty!")

'''
'''
def _SubscriptionConfirmation(  snsMessage):
	#logger.debug( snsMessage)

	if not 'SubscribeURL' in snsMessage:
			return connexion.problem( 400, "Subscription error", "No subscription URL was provided")
	
	subUrl = snsMessage[ 'SubscribeURL']

	'''
	Check subUrl is an URL
	^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+
	Long live regex101!!! :)
	'''
	if not re.match( '^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', subUrl):
		logger.error ( 'SubscribeURL is not an URL')
		return connexion.problem( 400, "Subscription error", "'%s' is not a valid SubscribeURL" % subUrl)

	try:
		r = requests.get( subUrl)
	except:
		logger.error( 'Unable to fetch: ' + subUrl)
		return connexion.problem( 404, "Subscription error", "Unable to fetch: '%s'" % subUrl)

	logger.debug( 'And got... %s' % r)
	return "SubscriptionConfirmation"

'''
'''
def _UnknownMessageType( snsMessage):
	logger.error( snsMessage['Type'] + ' is an unknown message type')
	return connexion.problem( 404, "Message Type error", 'Unknown message type: ' + snsMessage['Type'] )

'''
This handler is defined in Swagger. See swagger/swagger.yaml.
Headers are not (yet?) passed as arguments so there is only one: the SNS message.
The swagger model ensure that snsMessage exists and its format. So there is no extra check here.
'''
def sns_post( snsMessage ):

	logger.debug('Message received:\n---\n%s\n---\n' % snsMessage)

	if not 'Type' in snsMessage:	
		return connexion.problem( 400, "Format error", "No message Type specified" )

	'''
	Verify SNS message signature to ensure they are from AWS.
	Use boto3 module from Amazon if I find the function!??
	Check this URL for more info:
	http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html
	To be set with before_request
	'''

	# Step 1: Check if we have a signature
	if not 'Signature' in snsMessage:
		return connexion.problem( 400, "Signature error", "Message has no signature" )

	if not 'SignatureVersion' in snsMessage or snsMessage['SignatureVersion'] != 1:
		return connexion.problem( 400, "Signature error", "Unsupported signature version" )
	
	# Step 2: Get the certificate
	if not 'SigningCertURL' in snsMessage:
		return connexion.problem( 400, "Signature error", "No certificate specified." )
	else:
		# Will need to add a check on hostname sns...amazonaws.com
		if not re.match( '^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
					snsMessage['SigningCertURL']):
			return connexion.problem( 400, "Signature error",
				"'%s' is not a valid SigningCertURL" % snsMessage['SigningCertURL'])

	# Get certificate (and put it in cache one day...)
	try:
		r = requests.get( snsMessage['SigningCertURL'])
	except:
		logger.error( 'Unable to fetch certificate: ' + snsMessage['SigningCertURL'])
		return connexion.problem( 404, "Signature error",
				"Unable to fetch certificate %s" % snsMessage['SigningCertURL'] )
	
	awsCertificate = crypto.load_certificate( crypto.FILETYPE_PEM, r.text)

	# Step 3: Get the public key
	#awsPubKey = awsCertificate.get_pubkey()

	# Step 4: Determine type of message
	# Step 5: Build the string to sign
	myMessage = ''
	for name in [ 'Message', 'MessageId',  'Subject', 'SubscribeURL', 'Timestamp', 'Token',
			'TopicArn', 'Type']:
		if name in snsMessage:
			myMessage += '%s\n%s\n' % (name, snsMessage[name])

	#logger.debug( 'Message a signer:\n---\n%s---\n' % myMessage)

	# Step 6: Decode the Signature
	try: 
		awsSignature = b64decode( snsMessage['Signature'])
	except:
		return connexion.problem( 400, "Signature error", "Unable to decode signature." )

	# Step 7-9: compare
	crypto.verify( awsCertificate, awsSignature, myMessage, b'sha1')

	try:
		verify = crypto.verify( awsCertificate, awsSignature, myMessage, b'sha1')
	except:
		return connexion.problem( 401, "Signature error", "Signature doesn't match." )

	return {
		'UnsubscribeConfirmation': _UnsubscribeConfirmation,
		'SubscriptionConfirmation': _SubscriptionConfirmation,
		'Notification': _Notification,
	}.get( snsMessage['Type'], _UnknownMessageType )( snsMessage)

