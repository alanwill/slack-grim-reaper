import csv
import datetime
import json
import logging
import os
import tempfile

import boto3
from boto3.dynamodb.conditions import Key

from aws_xray_sdk.core import patch_all

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

# AWS X-Ray
patch_all()

# Initialize variables
stage = os.environ["STAGE"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
s3_bucket = os.environ["S3_BUCKET_NAME"]
s3_obj_key = "user_report/{:%Y-%m-%d-%H-%M-%S}.csv".format(
    datetime.datetime.now())


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    all_users = get_users(event.get('job_uuid'))
    active_users, inactive_users = bucket_users(all_users)

    user_summary(event.get('job_uuid'), inactive_users, 'inactive')
    user_summary(event.get('job_uuid'), active_users, 'active')

    active_user_report_link = generate_url(s3_obj_key, active_users, 'active')

    return {'job_uuid': event.get('job_uuid'),
        'active_user_report_link': active_user_report_link,
        'message_type': 'approval'
    }


def user_summary(job_uuid, user_list, category):
    table_userprocessing.put_item(
        Item={
            "pk": job_uuid,
            "sk": 'COUNT_' + str(category).upper(),
            "count": user_list.get(str(category).lower()).get('count')
        }
    )

    if category == 'inactive':
        # Clean list to only the value we want, SLACKID
        inactive_slack_ids = list()
        for user in user_list.get(str(category).lower()).get('users'):
            inactive_slack_ids.append('<@' + user['sk'].split('_')[1] + '>')

        table_userprocessing.put_item(
            Item={
                "pk": job_uuid,
                "sk": 'SUMMARY_' + str(category).upper() + '_USERS',
                "count": user_list.get(str(category).lower()).get('count'),
                "users": inactive_slack_ids
            }
        )


def get_users(job_uuid):
    all_users = list()
    response = table_userprocessing.query(
        KeyConditionExpression=Key('pk').eq(
            job_uuid) & Key('sk').begins_with('USER_')
    )

    # Paginate through results
    while 'LastEvaluatedKey' in response:
        for user in response.get('Items'):
            all_users.append(user)

        response = table_userprocessing.query(
            KeyConditionExpression=Key('pk').eq(
                job_uuid) & Key('sk').begins_with('USER_'),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )

    # Get the last paage
    for user in response.get('Items'):
        all_users.append(user)
    return all_users


def bucket_users(all_users):
    active = list()
    inactive = list()
    for user in all_users:
        if user.get('is_ad_active') == 'Y':
            active.append(user)
        elif user.get('is_ad_active') == 'N':
            inactive.append(user)

    num_active = len(active)
    num_inactive = len(inactive)

    return {"active": {"count": num_active, "users": active}}, \
        {"inactive": {"count": num_inactive, "users": inactive}}


def generate_csv(user_list, category):

    csv_list = list()
    for user in user_list.get(str(category).lower()).get('users'):
        csv_list.append([user['email'], user['department']])

    csv_file_path = os.path.join(tempfile.gettempdir(), 'slack_users.csv')

    with open(csv_file_path, 'w') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        for line in csv_list:
            writer.writerow(line)

    with open(csv_file_path, 'rb') as csv_file:
        s3.upload_fileobj(csv_file, s3_bucket, s3_obj_key)

    csv_file.close()


def generate_url(s3_obj_key, user_list, category):
    url = s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': s3_bucket,
            'Key': s3_obj_key
        },
        ExpiresIn=604800
    )

    generate_csv(user_list, category)

    return url
