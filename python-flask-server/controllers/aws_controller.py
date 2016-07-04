import requests
import connexion
import logging
import re

import boto3 # AWS SDK - https://boto3.readthedocs.io/en/latest/

# log files to be added...
logger = logging.getLogger( __name__)

'''
Verify SNS message signature to ensure they are from AWS.
Use boto3 module from Amazon if I find the function!??
Check this URL for more info:
http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html
'''
def _VerifySignature( msgBody, ignoreResult=False):

	if ignoreResult:
			logger.warning('Message signature ignored')

	# We must have a Signature, the certificate used and the version
	if not 'Signature' in msgBody:
		logger.error('No signature in message.')
		
		if not ignoreResult:
			return False

	if not 'SignatureVersion' in msgBody or msgBody['SignatureVersion'] != 1:
		logger.debug( 'unsupported SignatureVersion')
		if not ignoreResult:
			return False
	
	if not 'SigningCertURL' in msgBody:
		logger.error('No certificate specified')
		if not ignoreResult:
			return False
	else:
		if not re.match( '^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
					msgBody['SigningCertURL']):
			logger.error ( 'SigningCertURL is not an URL')
			return connexion.problem( 400, "Signature error",
				"'%s' is not a valid SigningCertURL" % msgBody['SigningCertURL'])


		# Get certificate (and put it in cache one day...)
		try:
			r = requests.get( msgBody['SigningCertURL'])
		except:
			logger.error( 'Unable to fetch certificate: ' + msgBody['SigningCertURL'])
	
		return True
		
	# No comment...
	return True



'''
One fonction per message type. Currently there are 3:
- Notification
- SubscriptionConfirmation
- unsubscribeConfirmation
The first one will receive all autoscaling group notifications and will have to handle devices' behavior.
Values are checked by swagger still the _UnknownMessageType() will be called if no match.
'''
def _Notification( msgBody):
	return connexion.problem( 404, "Notification error", "Don't be so hasty!")

'''
'''
def _UnsubscribeConfirmation( msgBody):
	return connexion.problem( 404, "Unsubscribe error", "Don't be so hasty!")

'''
'''
def _SubscriptionConfirmation(  msgBody):
	#logger.debug( msgBody)

	if not 'SubscribeURL' in msgBody:
			return connexion.problem( 400, "Subscription error", "No subscription URL was provided")
	
	subUrl = msgBody[ 'SubscribeURL']

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
		# Error code à revoir et ajouter du debug
		return connexion.problem( 404, "Subscription error", "Unable to fetch: '%s'" % subUrl)

	logger.debug( 'And got...' + r)
	return "SubscriptionConfirmation"

'''
'''
def _UnknownMessageType( msgBody):
	logger.error( msgBody['Type'] + ' is an unknown message type')
	return connexion.problem( 404, "Message Type error", 'Unknown message type: ' + msgBody['Type'] )

'''
This handler is defined in Swagger. See swagger/swagger.yaml.
Headers are not (yet?) passed as arguments so there is only one: the SNS message.
The swagger model ensure that snsMessage exists and its format. So there is no extra check here.
'''
def sns_post( snsMessage ) -> str:

	if not 'Type' in snsMessage:
			return "No message type specified", 400

	logger.debug('Message received:\n---\n%s\n---\n' % snsMessage)

	'''
	The third parameter of _VerifySignature is for debug only: it goes through the function
	but always return True
	'''
	'''
	if not _VerifySignature( snsMessage, True):
		logger.error( "Unable to verify message signature")
		return connexion.problem( 400, "Message signature error", "Unable to verify message signature")
	'''

	return {
		'UnsubscribeConfirmation': _UnsubscribeConfirmation,
		'SubscriptionConfirmation': _SubscriptionConfirmation,
		'Notification': _Notification,
	}.get( snsMessage['Type'], _UnknownMessageType )( snsMessage)

