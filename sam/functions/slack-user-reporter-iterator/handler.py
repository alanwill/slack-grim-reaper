# Generates iterator to loop through Slack user list

import logging
import boto3
import os
import sys
import json

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services

# Initialize variables


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    index = event['iterator']['index'] + 1
    guid = event['iterator']['guid']

    return {
        'index': index,
        'continue': index < event['iterator']['count'],
        'count': event['iterator']['count'],
        'guid': guid
    }