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

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory


# AWS X-Ray
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
s3 = boto3.resource('s3')
dynamodb = boto3.resource('dynamodb')

# Initialize variables
s3_bucket = os.environ["S3_BUCKET_NAME"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    generate_list(event['guid'])
    return


def generate_list(guid):
    user_list = list()
    response = table_userprocessing.query(
        KeyConditionExpression=Key('uuid').eq(guid),
        FilterExpression=Attr('status_code').eq(200)
    )

    for user in response['Items']:
        user_list.append([user['email'], user['department'], user['division']])

    convert_to_csv(user_list)


def convert_to_csv(buffer):
    csv_file_path = os.path.join(tempfile.gettempdir(), 'slack_users.csv')
    with open(csv_file_path, 'w') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        for line in buffer:
            writer.writerow(line)
        write_to_s3(csv_file_path)
    csv_file.close()

    return


def write_to_s3(file_path):

    s3.Bucket(s3_bucket).upload_file(file_path, "user_report/{:%Y-%m-%d-%H-%M-%S}.csv".format(datetime.datetime.now()))

    return
