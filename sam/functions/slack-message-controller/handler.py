# Slack controller

import logging
import boto3
import os
import sys
import json
import hmac
import hashlib
import time
import urllib.parse
from botocore.exceptions import ClientError

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# AWS X-Ray
# from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
secrets = boto3.client('secretsmanager')
sns = boto3.client('sns')

# Initialize variables
slack_secret = os.environ["SLACK_SECRET"]
slack_token = os.environ["SLACK_TOKEN"]
sns_topic_deactivate = os.environ["SNS_TOPIC_DEACTIVATE"]


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    if 'X-Slack-Signature' not in event['headers'] and \
            'X-Slack-Request-Timestamp' not in event['headers']:
        print("Payload doesn't have required fields")
        return {"statusCode": 400, "body": "Bad Request"}

    elif verify_request(secret=slack_secret, body=event['body'],
                        timestamp=event['headers']['X-Slack-Request-Timestamp'],
                        signature=event['headers']['X-Slack-Signature']) is False:
            print("Signature doesn't match")
            return {"statusCode": 400, "body": "Bad Request"}

    elif verify_request(secret=slack_secret, body=event['body'],
                        timestamp=event['headers']['X-Slack-Request-Timestamp'],
                        signature=event['headers']['X-Slack-Signature']) is True:
        payload = process_body(body=event['body'])

        if payload['actions'][0]['name'] == "no":
            print("User clicked NO")

            ts = payload['message_ts']
            text = payload['original_message']['text']
            channel = payload['channel']['id']
            attachments = [
                            payload['original_message']['attachments'][0],
                            {k: payload['original_message']['attachments'][1][k] for k in
                             set(list(payload['original_message']['attachments'][1].keys())) - {'actions'}},
                            {"text": "*:no_entry_sign: <@" + payload['user']['name'] +
                                     "> cancelled today's request. No further action will be taken.*",
                             "id": 3}
                           ]

            slack_response(text, channel, ts, attachments)
            return {"statusCode": 200}

        elif payload['actions'][0]['name'] == "yes":
            print("User clicked YES")

            ts = payload['message_ts']
            text = payload['original_message']['text']
            channel = payload['channel']['id']
            attachments = [
                            payload['original_message']['attachments'][0],
                            {k: payload['original_message']['attachments'][1][k] for k in
                             set(list(payload['original_message']['attachments'][1].keys())) - {'actions'}},
                            {"text": "*:white_check_mark: <@" + payload['user']['name'] +
                                     "> approved today's deprovisioning, I'll let you know once it's complete.*",
                             "id": 3}
                           ]

            slack_response(text, channel, ts, attachments)

            deactivate_users(callback_id=payload['callback_id'], callback_channel=channel)
            return {"statusCode": 200}

    print("No case fit")


def slack_response(text, channel, ts, attachments):
    message = {
        "text": text,
        "channel": channel,
        "ts": ts,
        "attachments": attachments
    }

    # print(json.dumps(message))
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + slack_token}
    response = requests.post('https://slack.com/api/chat.update', data=json.dumps(message), headers=headers)
    # print(response.content)

    if response.status_code != 200:
        raise Exception({"code": "5000", "message": "ERROR: Received unexpected response from Slack, " + response.text})


def verify_request(secret, body, timestamp, signature):
    print("Verifying request...")
    if abs(time.time() - int(timestamp)) > 60 * 5:
        print("Verify failed time verify")
        return False

    sig_basestring = 'v0:' + timestamp + ':' + body
    calculated_signature = 'v0=' + hmac.new(bytes(secret, 'utf-8'),
                                            bytes(sig_basestring, 'utf-8'),
                                            hashlib.sha256).hexdigest()

    if hmac.compare_digest(calculated_signature, signature):
        print("Verify passed")
        return True
    else:
        print("Verify failed hmac compare")
        return False


def process_body(body):

    payload = json.loads(urllib.parse.parse_qs(body)['payload'][0])

    print(json.dumps(payload))
    return payload


def deactivate_users(callback_id, callback_channel):
    guid = callback_id.split(":")[1]
    payload = '{"guid": "' + guid + '", "channel": "' + callback_channel + '"}'

    sns.publish(
        TopicArn=sns_topic_deactivate,
        Message='{"default": ' + payload + ', "lambda": ' + payload + ', "email": ' + payload + '}',
    )
