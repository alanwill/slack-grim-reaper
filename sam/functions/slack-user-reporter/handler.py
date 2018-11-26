# Function creates an S3 CSV of users per division

import logging
import boto3
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
import requests
from slackclient import SlackClient

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
s3 = boto3.resource('s3')


# Initialize variables
slack_token = os.environ["SLACK_TOKEN"]
azure_tenant_id = os.environ["AZURE_TENANT_ID"]
azure_client_id = os.environ["AZURE_CLIENT_ID"]
azure_client_secret = os.environ["AZURE_CLIENT_SECRET"]
access_token = ""
s3_bucket = os.environ["S3_BUCKET_NAME"]


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    csv_file_path = os.path.join(tempfile.gettempdir(), 'slack_users.csv')
    csv_file = open(csv_file_path, 'wb')
    csv_writer = csv.writer(csv_file)

    for member in slack_users()['members']:
        try:
            if member['deleted'] is False and member['name'] != 'slackbot':
                if azuread_users(member['profile']['email'], access_token)['status'] == 'OK':
                    with csv_file:
                        csv_writer.writerow([azuread_users(member['profile']['email'], access_token)['userPrincipalName'],
                                             azuread_users(member['profile']['email'], access_token)['department']])
        except KeyError as e:
            print("ERROR is:", e)
            print("KeyError generated from:", member)

    write_to_s3(csv_file)
    csv_file.close()

    return


def write_to_s3(file_object):

    s3.put_object(Bucket=s3_bucket,
                  Key="user_report/{:%Y-%m-%d-%H-%M-%S}.csv".format(datetime.datetime.now()),
                  Body=file_object)

    return


def slack_users():
    sc = SlackClient(slack_token)

    return sc.api_call("users.list")


def azure_auth(azure_tenant_id, azure_client_id, azure_client_secret):
    global access_token
    url = "https://login.microsoft.com/" + azure_tenant_id + "/oauth2/v2.0/token"

    payload = {'client_id': azure_client_id,
               'scope': 'https://graph.microsoft.com/.default',
               'client_secret': azure_client_secret,
               'grant_type': 'client_credentials'}

    headers = {'Content-Type': "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, data=payload, headers=headers)

    if response.status_code == 200:
        access_token = json.loads(response.content)['access_token']
        return access_token
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})


def azuread_users(user_email, access_token):
    headers = {'Authorization': 'Bearer ' + access_token}
    querystring = {'$select': 'department,displayName,userPrincipalName'}
    url = "https://graph.microsoft.com/v1.0/users/" + user_email

    response = requests.request("GET", url, params=querystring, headers=headers)
    print(response.status_code)
    print(response.content)

    if response.status_code == 401 and json.loads(response.content)['error']['code'] == 'InvalidAuthenticationToken':
        access_token = azure_auth(azure_tenant_id, azure_client_id, azure_client_secret)
        headers = {'Authorization': 'Bearer ' + access_token}
        querystring = {'$select': 'department,displayName,userPrincipalName'}
        url = "https://graph.microsoft.com/v1.0/users/" + user_email

        response = requests.request("GET", url, params=querystring, headers=headers)

        if response.status_code == 200:
            return {'status': 'OK',
                    'userPrincipalName': json.loads(response.content)['userPrincipalName'],
                    'department': json.loads(response.content)['department']
                    }
    elif response.status_code == 200:
        access_token = azure_auth(azure_tenant_id, azure_client_id, azure_client_secret)
        headers = {'Authorization': 'Bearer ' + access_token}
        querystring = {'$select': 'department,displayName,userPrincipalName'}
        url = "https://graph.microsoft.com/v1.0/users/" + user_email

        response = requests.request("GET", url, params=querystring, headers=headers)

        return {'status': 'OK',
                'userPrincipalName': json.loads(response.content)['userPrincipalName'],
                'department': json.loads(response.content)['department']
                }
    elif response.status_code == 404:
        return {'status': 'NOT_FOUND'}
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})
