# Function creates an S3 CSV of users per division

import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import json
import csv
import tempfile
import datetime
import re

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
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Initialize variables
s3_bucket = os.environ["S3_BUCKET_NAME"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
slack_token = os.environ["SLACK_TOKEN"]
slack_channel = os.environ["SLACK_CHANNEL"]
s3_obj_key = "user_report/{:%Y-%m-%d-%H-%M-%S}.csv".format(datetime.datetime.now())


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    convert_to_csv(buffer=generate_list(event['guid']))

    post_to_slack(url=generate_url(s3_obj_key), user_list=deactivate_user_list(event['guid']), guid=event['guid'])

    return


def generate_list(guid):
    user_list = list()
    response = table_userprocessing.query(
        KeyConditionExpression=Key('uuid').eq(guid),
        FilterExpression=Attr('status_code').eq(200)
    )

    for user in response['Items']:
        user_list.append([user['email'], user['department'], user['division']])

    return user_list


def convert_to_csv(buffer):
    csv_file_path = os.path.join(tempfile.gettempdir(), 'slack_users.csv')

    with open(csv_file_path, 'w') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        for line in buffer:
            writer.writerow(line)

    with open(csv_file_path, 'rb') as csv_file:
        s3.upload_fileobj(csv_file, s3_bucket, s3_obj_key)

    csv_file.close()

    return


def generate_url(s3_key):
    url = s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': s3_bucket,
            'Key': s3_key
        },
        ExpiresIn=604800
    )

    return url


def post_to_slack(url, user_list, guid):

    slack_message = {
        "channel": slack_channel,
        "text": "*Today's Slack Member actions*",
        "attachments": [
            {
                "title": "Active Member Breakdown Report",
                "title_link": str(url),
                "text": "Click the report above to download a csv of all Slack members broken out by department",
                "fallback": "Today's User Report URL is " + str(url),
                "color": "good"
            },
            {
                "title": "Member Deprovisioning",
                "text": "The following members no longer exist in the corporate identity system, "
                        "should I deactivate them?",
                "callback_id": "deactivate:" + guid,
                "color": "danger",
                "fields": [
                    {
                        "title": "Names",
                        "value": ", ".join(user_list),
                        "short": False
                    },
                    {
                        "title": "Count",
                        "value": str(len(user_list)),
                        "short": False
                    }
                ],
                "actions": [
                    {
                        "name": "yes",
                        "text": "Yes",
                        "type": "button",
                        "style": "danger",
                        "value": "yes"
                    },
                    {
                        "name": "no",
                        "text": "No",
                        "type": "button",
                        "style": "default",
                        "value": "no"
                    }
                ]
            }
        ]
    }

    # Send notification
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + slack_token}
    response = requests.post('https://slack.com/api/chat.postMessage', data=json.dumps(slack_message), headers=headers)
    # print(response.content)

    if response.status_code == 200:
        return


def deactivate_user_list(guid):
    user_list = list()

    response = table_userprocessing.query(
        KeyConditionExpression=Key('uuid').eq(guid),
        FilterExpression=Attr('status_code').eq(404)
    )

    for user in response['Items']:
        if re.search(r'\bautodesk.com\b', user['email']):
            user_list.append("<@" + user['slack_id'] + ">")

    return user_list
