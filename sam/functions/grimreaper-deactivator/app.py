import json
import logging
import os

import boto3
import requests

import grimreaper_common
from aws_xray_sdk.core import patch_all

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
dynamodb = boto3.resource('dynamodb')
ssm = boto3.client('ssm')

# AWS X-Ray
patch_all()

# Initialize variables
stage = os.environ["STAGE"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
slack_admin_token = json.loads(grimreaper_common.get_param(
    stage, 'slackAdminToken', secret=True)).get('token')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    users = get_users(event.get('job_uuid'))
    success, count = deactivate_users(users)
    if success is True:
        return {'message_type': 'deactivation_confirmation',
                'success': True,
                'job_uuid': event['job_uuid'],
                'count': count
                }
    if success is False:
        return {'message_type': 'deactivation_confirmation',
                'success': False,
                'job_uuid': event['job_uuid']
                }


def get_users(job_uuid):
    getUsers = table_userprocessing.get_item(
        Key={
            'pk': job_uuid,
            'sk': 'SUMMARY_INACTIVE_USERS'
        }
    )

    # Clean the userid of extra characters not needed for deactivation
    users = list()
    for user in getUsers['Item']['users']:
        users.append(user.strip('<@>'))
    return users


def deactivate_users(users_list):
    count_failure = 0
    count_success = 0

    for user in users_list:
        url = "https://api.slack.com/scim/v1/Users/" + user
        headers = {'Content-Type': 'application/json',
                   'Authorization': 'Bearer ' + slack_admin_token}
        response = requests.delete(url, headers=headers)

        if response.status_code == 200:
            count_success += 1
            continue
        else:
            count_failure += 1

    if count_failure > 1:
        return False, 0
    return True, count_success
