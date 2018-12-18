# Slack controller

import logging
import boto3
import os
import sys
import json
import hmac
import hashlib
import time
import base64
from botocore.exceptions import ClientError

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# AWS X-Ray
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
secrets = boto3.client('secretsmanager')

# Initialize variables


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    verify_request(secret=, body=event['body'],
                   timestamp=event['headers']['X-Slack-Request-Timestamp'],
                   signature=event['headers']['X-Slack-Signature'])

    slackWebhookEncrypted = getOpsTbl['Item']['slackWebhookEncrypted']
    slackHookUrl = "https://" + kms.decrypt(CiphertextBlob=b64decode(slackWebhookEncrypted))['Plaintext']

    try:
        if "Errors" in incomingMessage['Trigger']['MetricName'] \
                and "AWS/Lambda" in incomingMessage['Trigger']['Namespace']:
            newStateValue = incomingMessage['NewStateValue']
            reasonStateReason = incomingMessage['NewStateReason']
            functionName = incomingMessage['Trigger']['Dimensions'][0]['value']
            slackMessage = {
                "text": "I want to live! Please build me.",
                "attachments": [
                    {
                        "pretext": "I'll tell you how to set up your system.:robot_face:",
                        "text": "What operating system are you using?",
                        "callback_id": "os",
                        "color": "#3AA3E3",
                        "attachment_type": "default",
                        "actions": [
                            {
                                "name": "mac",
                                "text": ":apple: Mac",
                                "type": "button",
                                "value": "mac"
                            },
                            {
                                "name": "windows",
                                "text": ":fax: Windows",
                                "type": "button",
                                "value": "win"
                            }
                        ]
                    }
                ]
            }

            # Send notification
            slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
            print(slackWebhookResponse)
            return
    except Exception as e:
        print(e)
        print("Input not a Lambda error metric")


    return

def verify_request(secret, body, timestamp, signature):

    if abs(time.time() - timestamp) > 60 * 5:

        sig_basestring = 'v0:' + timestamp + ':' + body
        calculated_signature = 'v0=' + hmac.new(bytes(secret, 'utf-8'),
                                                bytes(sig_basestring, 'utf-8'),
                                                hashlib.sha256).hexdigest()

        if hmac.compare_digest(calculated_signature, signature):
            return True
        else:
            return False