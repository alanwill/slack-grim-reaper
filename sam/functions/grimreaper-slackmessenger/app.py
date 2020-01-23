import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse

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
sfn = boto3.client('stepfunctions')

# AWS X-Ray
patch_all()

# Initialize variables
stage = os.environ["STAGE"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
slack_channel = grimreaper_common.get_param(
    stage, 'slackChannel', secret=False)
slack_token = json.loads(grimreaper_common.get_param(
    stage, 'slackBotToken', secret=True)).get('token')
slack_secret = json.loads(grimreaper_common.get_param(
    stage, 'slackSigningSecret', secret=True)).get('token')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    if event.get('message_type') == 'approval':
        count, user_list = approval_get_info(event.get('job_uuid'))
        task_token_post(event.get('job_uuid'), event.get('task_token'))
        approval_post_to_slack(event.get('active_user_report_link'), event.get(
            'job_uuid'), count, user_list)
        return

    if event.get('headers') and 'X-Slack-Signature' in event['headers']:
        return process_slack_response(event)

    if event.get('message_type') == 'deactivation_confirmation':
        deactivation_confirmation(
            event.get('job_uuid'), event.get('success'), event.get('count'))


def verify_slack_request(secret, body, timestamp, signature):
    print("Verifying request...")
    if abs(time.time() - int(timestamp)) > 60 * 5:
        print("Verify failed - time")
        return False
    sig_basestring = 'v0:' + timestamp + ':' + body
    calculated_signature = 'v0=' + hmac.new(bytes(secret, 'utf-8'),
                                            bytes(sig_basestring, 'utf-8'),
                                            hashlib.sha256).hexdigest()
    if hmac.compare_digest(calculated_signature, signature):
        print("Verify passed")
        return True
    return False


def process_slack_response(event):

    if verify_slack_request(secret=slack_secret, body=event['body'],
            timestamp=event['headers']['X-Slack-Request-Timestamp'],
            signature=event['headers']['X-Slack-Signature']) is False:
        print("Bad Signature")
        return {"statusCode": 400, "body": "Bad Request"}

    if verify_slack_request(secret=slack_secret, body=event['body'],
            timestamp=event['headers']['X-Slack-Request-Timestamp'],
            signature=event['headers']['X-Slack-Signature']) is True:
        slack_payload = process_slack_body(body=event['body'])

        if slack_payload['actions'][0]['name'] == "no":
            print("Approval response is NO")
            return process_slack_approval('no', slack_payload)

        if slack_payload['actions'][0]['name'] == "yes":
            print("Approval response is YES")
            return process_slack_approval('yes', slack_payload)

        raise Exception({"code": "4000", "message": "ERROR: No case fit"})


def process_slack_approval(approval, slack_payload):
    if approval == 'no':
        ts = slack_payload['message_ts']
        text = slack_payload['original_message']['text']
        channel = slack_payload['channel']['id']
        attachments = [
            slack_payload['original_message']['attachments'][0],
            {k: slack_payload['original_message']['attachments'][1][k] for k in
             set(list(slack_payload['original_message']['attachments'][1].keys())) - {'actions'}},
            {"text": "*:no_entry_sign: <@" + slack_payload['user']['name'] +
             "> cancelled today's request. No further action will be taken.*",
             "id": 3}
        ]

        try:
            sfn_task_denied(task_token_get(
                slack_payload['callback_id']), slack_payload['callback_id'])
            approval_confirmation(text, channel, ts, attachments)
        except Exception as e:
            raise e

    elif approval == 'yes':
        ts = slack_payload['message_ts']
        text = slack_payload['original_message']['text']
        channel = slack_payload['channel']['id']
        attachments = [
            slack_payload['original_message']['attachments'][0],
            {k: slack_payload['original_message']['attachments'][1][k] for k in
             set(list(slack_payload['original_message']['attachments'][1].keys())) - {'actions'}},
            {"text": "*:white_check_mark: <@" + slack_payload['user']['name'] +
             "> approved today's user deactivation, I'll let you know once it's complete.*",
             "id": 3}
        ]

        try:
            sfn_task_approved(task_token_get(
                slack_payload['callback_id']), slack_payload['callback_id'])
            approval_confirmation(text, channel, ts, attachments)
        except Exception as e:
            raise e


def sfn_task_approved(task_token, job_uuid):

    try:
        sfn.send_task_success(
            taskToken=task_token,
            output=json.dumps({'job_uuid': job_uuid})
        )
    except Exception as e:
        raise e
    else:
        return True


def sfn_task_denied(task_token, job_uuid):

    try:
        sfn.send_task_failure(
            taskToken=task_token,
            error='denied',
            cause='Slack admin denied approval'
        )
    except Exception as e:
        raise e
    else:
        return True


def approval_confirmation(text, channel, ts, attachments):
    message = {
        "text": text,
        "channel": channel,
        "ts": ts,
        "attachments": attachments
    }

    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer ' + slack_token}
    response = requests.post(
        'https://slack.com/api/chat.update',
        data=json.dumps(message), headers=headers
    )

    if response.status_code != 200:
        raise Exception(
            {"code": "5000",
             "message": "ERROR: Received unexpected response from Slack, " +
             response.text}
        )


def process_slack_body(body):

    payload = json.loads(urllib.parse.parse_qs(body)['payload'][0])

    print(json.dumps(payload))
    return payload


def approval_get_info(job_uuid):

    getInfo = table_userprocessing.get_item(
        Key={
            'pk': job_uuid,
            'sk': 'SUMMARY_INACTIVE_USERS'
        }
    )

    return getInfo['Item']['count'], getInfo['Item']['users']


def approval_post_to_slack(report_url, job_uuid, count, user_list):

    slack_message = {
        "channel": slack_channel,
        "text": "*Today's Slack User actions*",
        "attachments": [
            {
                "title": "Active User Breakdown Report",
                "title_link": str(report_url),
                "text": "Click the report above to download a csv of all active Slack users broken out by department",
                "fallback": "Today's User Report URL is " + str(report_url),
                "color": "good"
            },
            {
                "title": "User Deprovisioning",
                "text": "The following users no longer exist in the corporate identity system, should I deactivate them?",
                "callback_id": job_uuid,
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
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer ' + slack_token}
    response = requests.post('https://slack.com/api/chat.postMessage',
                             data=json.dumps(slack_message), headers=headers)
    # print(response.content)

    if response.status_code == 200:
        return


def task_token_get(job_uuid):

    getTaskToken = table_userprocessing.get_item(
        Key={
            'pk': job_uuid,
            'sk': 'TASK_TOKEN_APPROVAL'
        }
    )

    return getTaskToken['Item']['token']


def task_token_post(job_uuid, task_token):

    table_userprocessing.put_item(
        Item={
            "pk": job_uuid,
            "sk": 'TASK_TOKEN_APPROVAL',
            "token": task_token
        }
    )


def deactivation_confirmation(job_uuid, success, count):
    if success is True:
        text = str(count) + " users disabled."
    elif success is False:
        text = "There was a problem disabling users, please check the logs."

    slack_message = {
        "channel": slack_channel,
        "text": text,
        "callback_id": job_uuid
    }

    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer ' + slack_token
               }
    response = requests.post('https://slack.com/api/chat.postMessage',
                             data=json.dumps(slack_message), headers=headers
                             )
    # print(response.content)

    if response.status_code == 200:
        return
