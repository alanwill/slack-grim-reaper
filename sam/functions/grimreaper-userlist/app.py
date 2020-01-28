import json
import logging
import os
import time
import uuid

import boto3
import requests
from boto3.dynamodb.conditions import Key

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

# Initialize env variables
stage = os.environ["STAGE"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
slack_token = json.loads(grimreaper_common.get_param(
    stage, 'slackBotToken', secret=True)).get('token')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    if not bool(event):
        # Get Slack members
        members = slack_members(slack_token, job_uuid=str(uuid.uuid4()))
        return members

    if event.get('next_cursor'):
        # Get Slack members
        members = slack_members(slack_token, next_cursor=event.get(
            'next_cursor'), job_uuid=event.get('job_uuid'))
        return members


def slack_members(slack_token, job_uuid, next_cursor=None):
    users_list = list()
    url = 'https://slack.com/api/users.list'
    params = {'limit': 200, 'token': slack_token, 'cursor': next_cursor}

    response = requests.request("GET", url, params=params)
    response_data = json.loads(response.content)
    next_cursor = response_data.get(
        'response_metadata', None).get('next_cursor', None)

    # TODO: Figure out why the statement above doesn't actually set the
    # next_cursor to None when it doesn't exist, negating the need
    # for the 2 lines below
    if next_cursor == '':
        next_cursor = None

    # Process response if bad auth or if being throttled, otherwise
    # continue assuming happy path
    if response.status_code == 200 and \
        json.loads(response.content).get('ok') is False:
            raise grimreaper_common.AuthException(
                'Something went wrong, likely bad auth'
            )

    if response.status_code == 429:
        print('Retry in:', response.headers['Retry-After'])
        retry = response.headers['Retry-After']

        if next_cursor is not None:
            raise grimreaper_common.TooManyRequestsException(
                {'job_uuid': job_uuid,
                'next_cursor': next_cursor, 'wait': retry}
            )

        # This would be a call that has <200 members, hence no pagination
        raise grimreaper_common.TooManyRequestsException(
            {'job_uuid': job_uuid, 'wait': retry}
        )

    # Parse all members for full Slack users
    for member in response_data.get('members'):
        if slack_active_user(member) is True \
            and member.get('id') != 'USLACKBOT':
                users_list.append([job_uuid,
                    member.get('profile').get('email'), member.get('id')]
                )
    print('Member list length:', len(response_data.get('members')))
    print('User list length:', len(users_list))
    dynamodb_write(job_uuid, users_list)

    if next_cursor is not None:
        return {'job_uuid': job_uuid,
            'next_cursor': next_cursor,
            'paginate': 1,
            'wait': 3
        }

    if next_cursor is None:
        return {'job_uuid': job_uuid, 'paginate': 0}


def slack_active_user(member):
    if member.get('deleted') is False and \
            member.get('is_bot') is False and \
            member.get('is_restricted') is False and \
            member.get('is_ultra_restricted') is False:
        return True
    else:
        return False


def dynamodb_write(job_uuid, users_list):
    # Get existing counter, if it exists
    get_count = table_userprocessing.query(
        KeyConditionExpression=Key('pk').eq(
            job_uuid) & Key('sk').begins_with('COUNT')
    )
    if get_count.get('Count') > 1:
        raise Exception('There should only be 1 item returned')

    if get_count.get('Count') == 0:
        # Add the count of the initial batch of users
        table_userprocessing.put_item(
            Item={
                "pk": job_uuid,
                "sk": 'COUNT_ALL_' + str(int(time.time())),
                "count": len(users_list)
            }
        )
    elif get_count.get('Count') == 1:
        # Udate the existing count of users
        table_userprocessing.put_item(
            Item={
                "pk": job_uuid,
                "sk": get_count.get('Items')[0].get('sk'),
                "count": len(users_list) + get_count.get('Items')[0].get('count')
            }
        )
    # Write each user
    with table_userprocessing.batch_writer() as batch:
        for i in users_list:
            batch.put_item(
                Item={
                    "pk": i[0],
                    "sk": 'USER_' + i[2],
                    "email": i[1],
                    "expiration_time": int(time.time() + 1296000)  # 15 days
                }
            )
