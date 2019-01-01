# Function creates an S3 CSV of users per division

import logging
import boto3
import os
import sys
import json

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))

# Modules downloaded into the vendored directory

# Logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initialize AWS services
s3 = boto3.resource('s3')
dynamodb = boto3.resource('dynamodb')



