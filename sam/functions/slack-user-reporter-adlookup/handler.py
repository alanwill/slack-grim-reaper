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
dynamodb = boto3.resource('dynamodb')


# Initialize variables
azure_tenant_id = os.environ["AZURE_TENANT_ID"]
azure_client_id = os.environ["AZURE_CLIENT_ID"]
azure_client_secret = os.environ["AZURE_CLIENT_SECRET"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    index = event['iterator']['index']
    guid = event['iterator']['guid']
    access_token = azure_auth(azure_tenant_id, azure_client_id, azure_client_secret)

    azuread_users(user_email=lookup_record(index, guid),
                  access_token=access_token,
                  guid=guid,
                  index=index)

    return


def lookup_record(index, guid):
    response = table_userprocessing.get_item(
        Key={
            'uuid': guid,
            'index': index
        }
    )

    email = response['Item']['email']

    return email


def update_record(index, guid, department, division):
    response = table_userprocessing.update_item(
        Key={
            'uuid': guid,
            'index': index
        },
        UpdateExpression='SET #department = :val1, '
                         '#division = :val2',
        ExpressionAttributeNames={'#department': 'department',
                                  '#division': 'division'},
        ExpressionAttributeValues={':val1': department,
                                   ':val2': division}
    )


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


def azuread_users(user_email, access_token, guid, index):
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
            update_record(index, guid, response_data['department'],
                          re.search('^([\w]+)', response_data['department']).group())
            return
    elif response.status_code == 200:
        update_record(index, guid, response_data['department'],
                      re.search('^([\w]+)', response_data['department']).group())
        return
    elif response.status_code == 404:
        return {'status': 'NOT_FOUND'}
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})
