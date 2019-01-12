import os
# import json
import uuid
# import pytest
import boto3
from boto3.dynamodb.conditions import Key
import sys
sys.path.append('../sam/functions/slack-user-reporter-userlist')
import handler

dynamodb = boto3.resource('dynamodb', endpoint_url="http://localhost:4569/")


def test_write_to_dynamodb():

    guid = str(uuid.uuid4())
    users = ["test@test.com", "U122345"]

    # create a table
    table = dynamodb.create_table(
        TableName=os.environ['USER_PROCESSING_TABLE'],
        KeySchema=[
            {
                'AttributeName': 'uuid',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'email',
                'KeyType': 'range'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'uuid',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'email',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'status_code',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        },
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsiStatusCode',
            'KeySchema': [{
                'AttributeName': 'status_code',
                'KeyType': 'HASH'
            }],
            'Projection': {
                'ProjectionType': 'ALL'
            },
            'ProvisionedThroughput': {
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        }]
    )

    handler.write_to_dynamodb(users, guid)

    response = table.query(
        KeyConditionExpression=Key('uuid').eq(guid),
    )

    actual = response['Items'][0]['uuid']
    expected = guid

    # check the content of the item
    assert actual == expected
