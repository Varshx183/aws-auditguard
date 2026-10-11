#!/usr/bin/env python3
"""Generate the one-time, operator-deployed OIDC bootstrap (standard AWS partition)."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
R = lambda name: {'Ref': name}
S = lambda text: {'Fn::Sub': text}
A = lambda name: {'Fn::GetAtt': [name, 'Arn']}

def allow(actions, resource, condition=None):
    value = {'Effect': 'Allow', 'Action': actions, 'Resource': resource}
    if condition:
        value['Condition'] = condition
    return value

def role(service, statements):
    return {'Type': 'AWS::IAM::Role', 'Properties': {
        'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': 'sts:AssumeRole'}]},
        'Policies': [{'PolicyName': 'AuditGuardScopedPermissions', 'PolicyDocument': {
            'Version': '2012-10-17', 'Statement': statements}}]}}

prefix = 'arn:${AWS::Partition}:'
regional = '${AWS::Region}:${AWS::AccountId}:'
function = S(prefix + 'lambda:' + regional + 'function:aws-auditguard-detection-detector')
queue = S(prefix + 'sqs:' + regional + 'aws-auditguard-detection-*')
log = S(prefix + 'logs:' + regional + 'log-group:/aws/lambda/aws-auditguard-detection-detector:*')
stack = S(prefix + 'cloudformation:' + regional + 'stack/aws-auditguard-detection/*')
region_condition = {'StringEquals': {'aws:RequestedRegion': R('AWS::Region')}}
t = {
 'AWSTemplateFormatVersion': '2010-09-09',
 'Description': 'Operator bootstrap: GitHub main branch OIDC, CloudFormation deployment role and fixed Lambda runtime role.',
 'Parameters': {
    'GitHubOidcSubject': {'Type': 'String', 'Default': 'repo:Varshx183@207301812/aws-auditguard@1413488585:ref:refs/heads/main',
        'Description': 'Exact immutable GitHub owner/repository subject, restricted to main.',
        'AllowedPattern': 'repo:[A-Za-z0-9_.-]+@[0-9]+/[A-Za-z0-9_.-]+@[0-9]+:ref:refs/heads/main'},
    'ExistingProviderArn': {'Type': 'String', 'Default': '', 'Description': 'Reuse an existing token.actions.githubusercontent.com IAM provider if present.'}},
 'Conditions': {'CreateProvider': {'Fn::Equals': [R('ExistingProviderArn'), '']}},
 'Resources': {}, 'Outputs': {}}
r=t['Resources']
r['GitHubProvider'] = {'Type': 'AWS::IAM::OIDCProvider', 'Condition': 'CreateProvider',
    'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain', 'Properties': {
        'Url': 'https://token.actions.githubusercontent.com', 'ClientIdList': ['sts.amazonaws.com']}}
r['RuntimeRole'] = role('lambda.amazonaws.com', [
    allow(['logs:CreateLogStream', 'logs:PutLogEvents'], log),
    allow('sns:Publish', S(prefix + 'sns:' + regional + 'aws-auditguard-AlertsTopic-*')),
    allow('sqs:SendMessage', S(prefix + 'sqs:' + regional + 'aws-auditguard-detection-processing-failures')),
    allow('ec2:DescribeSecurityGroupRules', '*', region_condition)])
r['CloudFormationRole'] = role('cloudformation.amazonaws.com', [
    allow(['lambda:CreateFunction', 'lambda:DeleteFunction', 'lambda:GetFunction', 'lambda:GetFunctionConfiguration',
           'lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration', 'lambda:AddPermission', 'lambda:RemovePermission',
           'lambda:GetPolicy', 'lambda:TagResource', 'lambda:UntagResource', 'lambda:ListTags',
           'lambda:PutFunctionEventInvokeConfig', 'lambda:UpdateFunctionEventInvokeConfig',
           'lambda:GetFunctionEventInvokeConfig', 'lambda:DeleteFunctionEventInvokeConfig'],
          [function, S(prefix + 'lambda:' + regional + 'function:aws-auditguard-detection-detector:*')]),
    allow(['logs:CreateLogGroup', 'logs:DeleteLogGroup', 'logs:PutRetentionPolicy', 'logs:DeleteRetentionPolicy',
           'logs:TagResource', 'logs:UntagResource', 'logs:ListTagsForResource', 'logs:TagLogGroup',
           'logs:UntagLogGroup', 'logs:ListTagsLogGroup'],
          [log, S(prefix + 'logs:' + regional + 'log-group:/aws/lambda/aws-auditguard-detection-detector')]),
    allow('logs:DescribeLogGroups', '*', region_condition),
    allow(['events:PutRule', 'events:DeleteRule', 'events:DescribeRule', 'events:PutTargets', 'events:RemoveTargets',
           'events:ListTargetsByRule', 'events:TagResource', 'events:UntagResource', 'events:ListTagsForResource'],
          S(prefix + 'events:' + regional + 'rule/aws-auditguard-detection-ingress')),
    allow(['sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:SetQueueAttributes', 'sqs:GetQueueAttributes',
           'sqs:GetQueueUrl', 'sqs:TagQueue', 'sqs:UntagQueue', 'sqs:ListQueueTags'], queue),
    allow(['cloudwatch:PutMetricAlarm', 'cloudwatch:DeleteAlarms', 'cloudwatch:DescribeAlarms',
           'cloudwatch:TagResource', 'cloudwatch:UntagResource', 'cloudwatch:ListTagsForResource'],
          S(prefix + 'cloudwatch:' + regional + 'alarm:aws-auditguard-detection-*')),
    allow('iam:PassRole', A('RuntimeRole'), {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}})])
r['GitHubDeployRole'] = {'Type': 'AWS::IAM::Role', 'Properties': {
    'MaxSessionDuration': 3600,
    'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Federated': {'Fn::If': ['CreateProvider', R('GitHubProvider'), R('ExistingProviderArn')]}},
        'Action': 'sts:AssumeRoleWithWebIdentity', 'Condition': {'StringEquals': {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
            'token.actions.githubusercontent.com:sub': R('GitHubOidcSubject')}}}]},
    'Policies': [{'PolicyName': 'DeployDetectionOnly', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
        allow('cloudformation:CreateChangeSet', stack,
              {'StringEquals': {'cloudformation:RoleArn': A('CloudFormationRole')}}),
        allow(['cloudformation:DescribeChangeSet', 'cloudformation:ExecuteChangeSet', 'cloudformation:DeleteChangeSet',
               'cloudformation:TagResource', 'cloudformation:UntagResource',
               'cloudformation:GetTemplateSummary'], stack),
        allow(['cloudformation:DescribeStacks', 'cloudformation:DescribeStackEvents'],
              [stack, S(prefix+'cloudformation:'+regional+'stack/aws-auditguard/*')]),
        allow('cloudformation:DeleteStack', stack,
              {'StringEquals': {'cloudformation:RoleArn': A('CloudFormationRole')}}),
        allow('iam:PassRole', A('CloudFormationRole'),
              {'StringEquals': {'iam:PassedToService': 'cloudformation.amazonaws.com'}})
    ]}}]}}
for name in ['GitHubDeployRole', 'CloudFormationRole', 'RuntimeRole']:
    t['Outputs'][name+'Arn'] = {'Value': A(name)}
t['Outputs']['ProviderArn'] = {'Value': {'Fn::If': ['CreateProvider', R('GitHubProvider'), R('ExistingProviderArn')]}}
(root / 'infrastructure/github-oidc.json').write_text(json.dumps(t, indent=2)+'\n')
