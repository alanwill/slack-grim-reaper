# Function creates an S3 CSV of users per division

import logging
import boto3
import os
import sys
import json
import uuid
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

# Initialize AWS services (testing is done with localstack when AWS_SAM_LOCAL env is set
if os.getenv("AWS_SAM_LOCAL"):
    dynamodb = boto3.resource('dynamodb', endpoint_url="http://localhost:4569/")
    s3 = boto3.resource('s3', endpoint_url="http://localhost:4572/")
else:
    dynamodb = boto3.resource('dynamodb')
    s3 = boto3.resource('s3')

# Initialize variables
slack_token = os.environ["SLACK_TOKEN"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    slack_users, guid = slack_active_users()[0], slack_active_users()[1]

    return {
                'count': len(slack_users),
                'guid': guid
            }


def slack_active_users():

    url = 'https://slack.com/api/users.list'
    params = {'limit': 200,
              'token': slack_token}

    response = requests.request("GET", url, params=params)
    response_data = json.loads(response.content)

    users = list()
    guid = str(uuid.uuid4())

    while response_data['response_metadata'].get('next_cursor'):
        for user in response_data['members']:
            try:
                if user['deleted'] is False and \
                        user['is_bot'] is False and \
                        user['is_restricted'] is False and \
                        user['is_ultra_restricted'] is False:
                    users.append([user['profile']['email'], user['id']])
            except KeyError as e:
                print("ERROR is:", e)
                print("KeyError generated from:", user)

        next_cursor = response_data['response_metadata']['next_cursor']
        params = {'limit': 500,
                  'cursor': next_cursor,
                  'token': slack_token}
        response = requests.request("GET", url, params=params)
        response_data = json.loads(response.content)

    # print("length of users is", len(users))

    write_to_dynamodb(users, guid)

    return users, guid


def write_to_dynamodb(users, guid):

    # Write to DynamoDB
    for email in users:
        try:
            table_userprocessing.put_item(
                Item={
                    "uuid": guid,
                    "email": email[0].lower(),
                    "slack_id": email[1]
                }
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'InternalServerError':
                # retry
                raise e
            elif e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                # print and escalate
                raise e
            elif e.response['Error']['Code'] == 'ItemCollectionSizeLimitExceededException':
                raise e
            elif e.response['Error']['Code'] == 'RequestLimitExceeded':
                # retry
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # print and escalate
                raise e
            elif e.response['Error']['Code'] == 'TransactionConflictException':
                # print and escalate
                raise e

    return


