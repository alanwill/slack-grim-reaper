# Function creates an S3 CSV of users per division

import logging
import boto3
from boto3.dynamodb.conditions import Key
import os
import sys
import json
import re
import concurrent.futures

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# AWS X-Ray
# from aws_xray_sdk.core import xray_recorder
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

    user_list = lookup_users(event['guid'])
    access_token = azure_auth()

    num_workers = 1000

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(azuread_users, user, access_token, event['guid']) for user in user_list}
        concurrent.futures.wait(futures)

    return {
                'guid': event['guid']
            }


def lookup_users(guid):
    user_list = list()

    # Execute the initial query
    response = table_userprocessing.query(
        KeyConditionExpression=Key('guid').eq(guid)
    )

    # If result is paginated, the LastEvaluatedKey field will be returned in the response. Keep paging
    # until LastEvaluatedKey field is no longer returned, i.e. the last page
    while 'LastEvaluatedKey' in response:
        for user in response['Items']:
            if re.search(r'\bautodesk.com\b', user['email']):
                user_list.append(user['email'])

        response = table_userprocessing.query(
            KeyConditionExpression=Key('guid').eq(guid),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )

    # Since LastEvaluatedKey is not returned in the last page, in order to grab results in the last page
    # we need a loop for the final page
    for user in response['Items']:
        if re.search(r'\bautodesk.com\b', user['email']):
            user_list.append(user['email'])

    print(user_list)
    return user_list


def update_record(email, guid, department, division, status_code):
    if status_code == 200:
        table_userprocessing.update_item(
            Key={
                'guid': guid,
                'email': email
            },
            UpdateExpression='SET #department = :val1, '
                             '#division = :val2, '
                             '#status_code = :val3',
            ExpressionAttributeNames={'#department': 'department',
                                      '#division': 'division',
                                      '#status_code': 'status_code'},
            ExpressionAttributeValues={':val1': department,
                                       ':val2': division,
                                       ':val3': status_code}
        )
    elif status_code == 404:
        table_userprocessing.update_item(
            Key={
                'guid': guid,
                'email': email
            },
            UpdateExpression='SET #status_code = :val1',
            ExpressionAttributeNames={'#status_code': 'status_code'},
            ExpressionAttributeValues={':val1': status_code}
        )


def azure_auth():
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


def azuread_users(user_email, access_token, guid):
    headers = {'Authorization': 'Bearer ' + access_token}
    querystring = {'filter': 'mail eq \'' + user_email +
                             '\' or userPrincipalName eq \'' + user_email +
                             '\' or proxyAddresses/any(x:x eq \'SMTP:' + user_email +
                             '\')'}
    url = "https://graph.microsoft.com/beta/users"

    response = requests.request("GET", url, params=querystring, headers=headers)
    response_data = json.loads(response.content)

    if response.status_code == 401 and response_data['error']['code'] == 'InvalidAuthenticationToken':
        access_token = azure_auth()
        headers = {'Authorization': 'Bearer ' + access_token}
        querystring = {'filter': 'mail eq \'' + user_email +
                                 '\' or userPrincipalName eq \'' + user_email +
                                 '\' or proxyAddresses/any(x:x eq \'SMTP:' + user_email +
                                 '\')'}
        url = "https://graph.microsoft.com/beta/users"
        response = requests.request("GET", url, params=querystring, headers=headers)
        response_data = json.loads(response.content)

        if response.status_code == 200 and response_data['value'][0]['accountEnabled'] is True:

            process_200(user_email, response_data, response.status_code, guid)

    elif response.status_code == 200 and response_data['value'][0]['accountEnabled'] is True:
        process_200(user_email, response_data, response.status_code, guid)

    elif response.status_code == 200 and response_data['value'][0]['accountEnabled'] is False:
        update_record(email=user_email,
                      guid=guid,
                      department="",
                      division="",
                      status_code=404)
        print(user_email, "is a disabled account.")
    elif response.status_code == 200 and 'accountEnabled' not in response_data['value'][0]:
        update_record(email=user_email,
                      guid=guid,
                      department="",
                      division="",
                      status_code=404)
        print(user_email, "was was not found.")
    else:
        raise Exception({"code": "5000", "message": "ERROR: Unable to retrieve Azure Auth Token"})


def process_200(user_email, response_data, status_code, guid):
    proxy_address_smtp = user_email

    # Extract SMTP proxyAddresses from payload
    for i in response_data['value'][0]['proxyAddresses']:
        if i.startswith('SMTP'):
            proxy_address_smtp = i.split(':')[1]

    # Create a dictionary with possible options for valid email
    options = [response_data['value'][0]['mail'].lower(),
               response_data['value'][0]['userPrincipalName'].lower(),
               proxy_address_smtp]

    # If there's a match, use that to match DynamoDB value
    for i in options:
        if user_email == i:
            update_record(email=i,
                          guid=guid,
                          department=response_data['value'][0]['department'],
                          division=re.search('^([\w]+)', response_data['value'][0]['department']).group(),
                          status_code=status_code)
        else:
            pass
