# Function creates an S3 CSV of users per division

import logging
import boto3
import os
import sys
import json
import csv
import tempfile
import datetime
import re
import uuid

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
s3 = boto3.resource('s3')
dynamodb = boto3.resource('dynamodb')

# Initialize variables
slack_token = os.environ["SLACK_TOKEN"]
#azure_tenant_id = os.environ["AZURE_TENANT_ID"]
#azure_client_id = os.environ["AZURE_CLIENT_ID"]
#azure_client_secret = os.environ["AZURE_CLIENT_SECRET"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    # user_list = list()
    slack_users, guid = slack_active_users()[0], slack_active_users()[1]
    #
    # access_token = azure_auth(azure_tenant_id, azure_client_id, azure_client_secret)
    #
    # for user in slack_users:
    #     azuread_response = azuread_users(user, access_token)
    #     if azuread_response['status'] == 'OK':
    #         user_list.append([azuread_response['email'],
    #                          azuread_response['department'],
    #                          azuread_response['division']])
    #
    # print("length of user_list is", len(user_list))
    # convert_to_csv(user_list)

    return {'iterator':
            {
                    'count': len(slack_users),
                    'index': 0,
                    'step': 1,
                    'guid': guid
            }}


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
                    users.append(user['profile']['email'])
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


def write_to_dynamodb(users, uuid):
    count = 0

    # Write to DynamoDB
    for email in users:
        count += 1
        table_userprocessing.put_item(
            Item={
                "uuid": uuid,
                "index": count,
                "email": email,
            }
        )

    return


def azure_auth(azure_tenant_id, azure_client_id, azure_client_secret):
    url = "https://login.microsoft.com/" + azure_tenant_id + "/oauth2/v2.0/token"

    payload = {'client_id': azure_client_id,
               'scope': 'https://graph.microsoft.com/.default',
               'client_secret': azure_client_secret,
               'grant_type': 'client_credentials'}

    headers = {'Content-Type': "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, data=payload, headers=headers)
    response_data = json.loads(response.content)

    if response.status_code == 200:
        access_token = response_data['access_token']
        return access_token
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})


def azuread_users(user_email, access_token):
    headers = {'Authorization': 'Bearer ' + access_token}
    querystring = {'$select': 'department,displayName,userPrincipalName'}
    url = "https://graph.microsoft.com/v1.0/users/" + user_email

    response = requests.request("GET", url, params=querystring, headers=headers)
    response_data = json.loads(response.content)

    if response.status_code == 401 and response_data['error']['code'] == 'InvalidAuthenticationToken':
        access_token = azure_auth(azure_tenant_id, azure_client_id, azure_client_secret)
        headers = {'Authorization': 'Bearer ' + access_token}
        querystring = {'$select': 'department,displayName,userPrincipalName'}
        url = "https://graph.microsoft.com/v1.0/users/" + user_email

        response = requests.request("GET", url, params=querystring, headers=headers)
        response_data = json.loads(response.content)

        if response.status_code == 200:
            return {'status': 'OK',
                    'email': response_data['userPrincipalName'],
                    'department': response_data['department'],
                    'division': re.search('^([\w]+)', response_data['department']).group()
                    }
    elif response.status_code == 200:

        return {'status': 'OK',
                'email': response_data['userPrincipalName'],
                'department': response_data['department'],
                'division': re.search('^([\w]+)', response_data['department']).group()
                }
    elif response.status_code == 404:
        return {'status': 'NOT_FOUND'}
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})
