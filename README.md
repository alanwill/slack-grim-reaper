[![Codacy Badge](https://api.codacy.com/project/badge/Grade/0d123abb57614879bae3dfc90b71be26)](https://app.codacy.com/app/alanwill/slack-grim-reaper?utm_source=github.com&utm_medium=referral&utm_content=alanwill/slack-grim-reaper&utm_campaign=Badge_Grade_Dashboard) [![CodeFactor](https://www.codefactor.io/repository/github/alanwill/slack-grim-reaper/badge/master)](https://www.codefactor.io/repository/github/alanwill/slack-grim-reaper/overview/master) [![Total alerts](https://img.shields.io/lgtm/alerts/g/alanwill/slack-grim-reaper.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/alanwill/slack-grim-reaper/alerts/) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/alanwill/slack-grim-reaper.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/alanwill/slack-grim-reaper/context:python) [![Maintainability](https://api.codeclimate.com/v1/badges/bf759dfe9c70aba8f97f/maintainability)](https://codeclimate.com/github/alanwill/slack-grim-reaper/maintainability)

# Slack Grim Reaper

## What is it

The Grim Reaper is a Slack App that deactivates user accounts no longer associated with an Azure AD instance. The company identity provider currently supported is Azure AD and others can be integrated if needed.

Grim Reaper is built wholy in AWS and is initiated via a daily Cloudwatch Rules job. All compute components are Lambda based and the workflow is orchestrated using Step Functions. There is an API Gateway for receiving responses from Slack as part of the bot's messenger feature. The entire application is codified and deployed using SAM.

## Logical Design

The following logical design represents the Step Functions steps:

![logical design](assets/stepfunctions_graph.png)

## Physical Design

The following physical design represents the overall AWS architecture:

![physical design](assets/grim_reaper_physical.png)
