import json
import logging
import os

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

# Initialize variables
stage = os.environ["STAGE"]
table_userprocessing = dynamodb.Table(os.environ['USER_PROCESSING_TABLE'])
azure_tenant_id = grimreaper_common.get_param(
    stage, 'azureTenantId', secret=False)
azure_client_id = grimreaper_common.get_param(
    stage, 'azureClientId', secret=False)
azure_client_secret = json.loads(grimreaper_common.get_param(
    stage, 'azureClientSecret', secret=True)).get('token')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    users = get_users(event['job_uuid'])
    if users.get('count') == 0:
        return {'count': 0, 'job_uuid': event['job_uuid']}

    if users.get('count') > 0:
        azure_token = azure_auth()
        processed_users = azure_check_users(users, azure_token)
        dynamodb_write(event['job_uuid'], processed_users)
        return {'count': users.get('count'), 'job_uuid': event['job_uuid']}


def get_users(job_uuid):
    # Execute the initial query
    response = table_userprocessing.query(
        KeyConditionExpression=Key('pk').eq(
            job_uuid) & Key('sk').begins_with('USER_'),
        FilterExpression="attribute_not_exists(is_ad_active)"
    )
    count = 0
    user_list = list()
    if response.get('Count') > 0:
        for user in response.get('Items'):
            user_list.append([user['sk'], user['email']])
            count = count + 1
            if count == 200:
                break
        return {'count': response.get('Count'),
            'user_list': user_list,
            'job_uuid': job_uuid
        }

    if response.get('Count') == 0 and response.get('LastEvaluatedKey'):
        response2 = table_userprocessing.query(
            KeyConditionExpression=Key('pk').eq(
                job_uuid) & Key('sk').begins_with('USER_'),
            FilterExpression="attribute_not_exists(is_ad_active)",
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        # If result is paginated, the LastEvaluatedKey field will be returned
        # in the response. Keep paging until LastEvaluatedKey field is no
        # longer returned, i.e. the last page
        if 'LastEvaluatedKey' not in response2:
                for user in response2.get('Items'):
                    user_list.append([user['sk'], user['email']])
                    count = count + 1
                    if count == 200:
                        break
        else:
            while 'LastEvaluatedKey' in response2:
                for user in response2.get('Items'):
                    user_list.append([user['sk'], user['email']])
                    count = count + 1
                    if count == 200:
                        break
        return {'count': response2.get('Count'),
            'user_list': user_list,
            'job_uuid': job_uuid
        }
    return {'count': 0}


def azure_auth():
    url = "https://login.microsoft.com/" + azure_tenant_id + \
        "/oauth2/v2.0/token"
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

    raise Exception(
        {"code": "5000",
        "message": "ERROR: Unable to retrieve Azure Auth Token"}
    )


def azure_check_users(users, azure_token):
    processed = list()
    if users.get('count') == 0:
        return

    for sk, email in users.get('user_list'):
        lookup = azure_ad_lookup(email, azure_token)
        processed.append([sk, email, lookup.get(
            'is_ad_active'), lookup.get('department', None)])

    return processed


def azure_ad_lookup(user_email, azure_token):
    headers = {'Authorization': 'Bearer ' + azure_token}
    querystring = {'filter': 'mail eq \'' + user_email +
                             '\' or userPrincipalName eq \'' + user_email +
                             '\' or proxyAddresses/any(x:x eq \'SMTP:' + user_email +
                             '\')'}
    url = "https://graph.microsoft.com/beta/users"

    response = requests.request("GET", url, params=querystring,
                                headers=headers)
    response_data = json.loads(response.content)

    if response.status_code == 401 and \
        response_data['error']['code'] == 'InvalidAuthenticationToken':
            access_token = azure_auth()
            headers = {'Authorization': 'Bearer ' + access_token}
            querystring = {'filter': 'mail eq \'' + user_email +
                                    '\' or userPrincipalName eq \'' + user_email +
                                    '\' or proxyAddresses/any(x:x eq \'SMTP:' + user_email +
                                    '\')'}
            url = "https://graph.microsoft.com/beta/users"
            response = requests.request(
                "GET", url, params=querystring, headers=headers)
            response_data = json.loads(response.content)

    if response.status_code == 500:
        raise ConnectionError("Received status code 500")

    if response.status_code == 200 and not response_data['value']:
        return {'is_ad_active': 'N'}

    if response.status_code == 200 and \
        response_data['value'][0].get('accountEnabled') is False:
            return {'is_ad_active': 'N'}

    if response.status_code == 200 and \
        'accountEnabled' not in response_data['value'][0]:
            return {'is_ad_active': 'N'}

    if response.status_code == 200 and \
        response_data['value'][0].get('accountEnabled') is True:
            return {'is_ad_active': 'Y',
                'department': response_data['value'][0].get('department')
            }
    raise Exception(
        {"code": "5000",
        "message": "ERROR: Unable to retrieve Azure Auth Token"}
    )


def dynamodb_write(job_uuid, processed_users):
    # Write each user
    with table_userprocessing.batch_writer() as batch:
        for i in processed_users:
            batch.put_item(
                Item={
                    "pk": job_uuid,
                    "sk": i[0],
                    "email": i[1],
                    "is_ad_active": i[2],
                    "department": i[3]
                }
            )
