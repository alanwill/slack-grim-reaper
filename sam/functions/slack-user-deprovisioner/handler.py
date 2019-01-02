# Slack controller

import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import json
import re
import hmac
import hashlib
import time
import urllib.parse
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
dynamodb = boto3.resource('dynamodb')

# Initialize variables
slack_secret = os.environ["SLACK_SECRET"]
slack_token = os.environ["SLACK_TOKEN"]
slack_admin_token = os.environ["SLACK_ADMIN_TOKEN"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    message = json.loads(event['Records'][0]['Sns']['Message'])
    print(message)

    users = lookup_users(message['default']['guid'])
    if deactivate_user_list(users) is True:
        post_to_slack(channel=message['default']['channel'],
                      callback_id="deactivate:" + message['default']['guid'],
                      text=str(len(users)) + " members have been disabled.")
    else:
        post_to_slack(channel=message['default']['channel'],
                      callback_id="deactivate:" + message['default']['guid'],
                      text="There was a problem disabling members, please check the logs.")

    return


def lookup_users(guid):
    user_list = list()

    response = table_userprocessing.query(
        KeyConditionExpression=Key('uuid').eq(guid),
        FilterExpression=Attr('status_code').ne(200)
    )

    for user in response['Items']:
        if re.search(r'\bautodesk.com\b', user['email']):
            user_list.append(user['slack_id'])

    print(user_list)
    return user_list


def deactivate_user_list(user_list):

    count_failure = 0

    for user in user_list:

        url = "https://api.slack.com/scim/v1/Users/" + user
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + slack_admin_token}
        response = requests.delete(url, headers=headers)

        if response.status_code == 200:
            continue
        else:
            count_failure += 1

    if count_failure > 1:
        return False
    else:
        return True


def post_to_slack(channel, callback_id, text):

    slack_message = {
        "channel": channel,
        "text": text,
        "callback_id": callback_id
    }

    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + slack_token}
    response = requests.post('https://slack.com/api/chat.postMessage', data=json.dumps(slack_message), headers=headers)
    # print(response.content)

    if response.status_code == 200:
        return
