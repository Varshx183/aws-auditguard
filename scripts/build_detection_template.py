#!/usr/bin/env python3
"""Build a standalone CloudFormation add-on with the tested inline Lambda source."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
ref = lambda name: {'Ref': name}
attr = lambda name, field: {'Fn::GetAtt': [name, field]}
sub = lambda value: {'Fn::Sub': value}
template = {
    'AWSTemplateFormatVersion': '2010-09-09',
    'Description': 'AuditGuard optional world-open SSH detection; requires an active regional CloudTrail trail.',
    'Parameters': {'AlertTopicArn': {'Type': 'String', 'Description': 'Existing same-account, same-Region SNS topic ARN with a confirmed subscription.'}},
    'Resources': {
        'DetectorLogs': {'Type': 'AWS::Logs::LogGroup', 'Properties': {
            'LogGroupName': sub('/aws/lambda/${AWS::StackName}-detector'), 'RetentionInDays': 7}},
        'DetectorRole': {'Type': 'AWS::IAM::Role', 'Properties': {
            'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]},
            'Policies': [{'PolicyName': 'DetectAndNotify', 'PolicyDocument': {
                'Version': '2012-10-17', 'Statement': [
                    {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': attr('DetectorLogs', 'Arn')},
                    {'Effect': 'Allow', 'Action': 'sns:Publish', 'Resource': ref('AlertTopicArn')}]}}]}},
        'Detector': {'Type': 'AWS::Lambda::Function', 'Properties': {
            'FunctionName': sub('${AWS::StackName}-detector'), 'Runtime': 'python3.12', 'Handler': 'index.handler',
            'Role': attr('DetectorRole', 'Arn'), 'Timeout': 15, 'MemorySize': 128,
            'Environment': {'Variables': {'ALERT_TOPIC_ARN': ref('AlertTopicArn')}},
            'Code': {'ZipFile': (root / 'detection/risky_ssh.py').read_text()}}},
        'IngressRule': {'Type': 'AWS::Events::Rule', 'Properties': {
            'Description': 'Evaluate successful ingress authorization calls for world-open SSH.',
            'State': 'ENABLED', 'EventPattern': {'source': ['aws.ec2'],
                'detail-type': ['AWS API Call via CloudTrail'],
                'detail': {'eventSource': ['ec2.amazonaws.com'], 'eventName': ['AuthorizeSecurityGroupIngress'],
                           'errorCode': [{'exists': False}]}},
            'Targets': [{'Id': 'RiskySshDetector', 'Arn': attr('Detector', 'Arn'),
                         'RetryPolicy': {'MaximumRetryAttempts': 2, 'MaximumEventAgeInSeconds': 3600}}]}},
        'InvokePermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {
            'Action': 'lambda:InvokeFunction', 'FunctionName': ref('Detector'),
            'Principal': 'events.amazonaws.com', 'SourceArn': attr('IngressRule', 'Arn'),
            'SourceAccount': ref('AWS::AccountId')}}
    },
    'Outputs': {'FunctionName': {'Value': ref('Detector')}, 'RuleName': {'Value': ref('IngressRule')},
                'LogGroupName': {'Value': ref('DetectorLogs')}}
}
# Use a bootstrap-owned runtime role for OIDC deployment; direct CloudShell
# deployment can still create the original stack-owned role.
template['Parameters'].update({
    'RuntimeRoleArn': {'Type': 'String', 'Default': '', 'Description': 'Optional pre-provisioned Lambda role for OIDC deployments.'},
    'EnableFailureSimulation': {'Type': 'String', 'Default': 'false', 'AllowedValues': ['true', 'false'],
                                'Description': 'Enable only for the synthetic asynchronous failure exercise.'}
})
template['Conditions'] = {'CreateRuntimeRole': {'Fn::Equals': [ref('RuntimeRoleArn'), '']}}
r = template['Resources']
r['DetectorRole']['Condition'] = 'CreateRuntimeRole'
r['DetectorRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'].extend([
    {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': attr('ProcessingFailures', 'Arn')},
    {'Effect': 'Allow', 'Action': 'ec2:DescribeSecurityGroupRules', 'Resource': '*',
     'Condition': {'StringEquals': {'aws:RequestedRegion': ref('AWS::Region')}}}
])
r['Detector']['Properties']['Role'] = {'Fn::If': ['CreateRuntimeRole', attr('DetectorRole', 'Arn'), ref('RuntimeRoleArn')]}
r['Detector']['DependsOn'] = 'DetectorLogs'
r['Detector']['Properties']['Environment']['Variables']['ENABLE_FAILURE_SIMULATION'] = ref('EnableFailureSimulation')
for logical, suffix in [('DeliveryFailures', 'delivery-failures'), ('ProcessingFailures', 'processing-failures')]:
    r[logical] = {'Type': 'AWS::SQS::Queue', 'Properties': {
        'QueueName': sub('${AWS::StackName}-' + suffix), 'SqsManagedSseEnabled': True,
        'MessageRetentionPeriod': 1209600, 'VisibilityTimeout': 120}}
r['DeliveryQueuePolicy'] = {'Type': 'AWS::SQS::QueuePolicy', 'Properties': {
    'Queues': [ref('DeliveryFailures')], 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'events.amazonaws.com'}, 'Action': 'sqs:SendMessage',
        'Resource': attr('DeliveryFailures', 'Arn'), 'Condition': {'ArnEquals': {
            'aws:SourceArn': sub('arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/${AWS::StackName}-ingress')}}}]}}}
r['AsyncFailureDestination'] = {'Type': 'AWS::Lambda::EventInvokeConfig', 'Properties': {
    'FunctionName': ref('Detector'), 'Qualifier': '$LATEST', 'MaximumRetryAttempts': 2,
    'MaximumEventAgeInSeconds': 3600,
    'DestinationConfig': {'OnFailure': {'Destination': attr('ProcessingFailures', 'Arn')}}}}
r['IngressRule']['DependsOn'] = ['DeliveryQueuePolicy', 'AsyncFailureDestination']
r['IngressRule']['Properties']['Name'] = sub('${AWS::StackName}-ingress')
r['IngressRule']['Properties']['EventPattern']['detail']['eventName'].append('ModifySecurityGroupRules')
r['IngressRule']['Properties']['Targets'][0]['DeadLetterConfig'] = {'Arn': attr('DeliveryFailures', 'Arn')}

def alarm(logical, suffix, namespace, metric, dimension, statistic='Sum'):
    r[logical] = {'Type': 'AWS::CloudWatch::Alarm', 'Properties': {
        'AlarmName': sub('${AWS::StackName}-' + suffix), 'Namespace': namespace,
        'MetricName': metric, 'Dimensions': [dimension], 'Statistic': statistic,
        'Period': 60, 'EvaluationPeriods': 1, 'Threshold': 1,
        'ComparisonOperator': 'GreaterThanOrEqualToThreshold', 'TreatMissingData': 'notBreaching',
        'AlarmActions': [ref('AlertTopicArn')]}}
for logical, metric in [('LambdaErrors', 'Errors'), ('LambdaThrottles', 'Throttles'),
                        ('DestinationErrors', 'DestinationDeliveryFailures')]:
    alarm(logical, metric.lower(), 'AWS/Lambda', metric, {'Name': 'FunctionName', 'Value': ref('Detector')})
for logical in ('DeliveryFailures', 'ProcessingFailures'):
    alarm(logical + 'Alarm', logical.lower(), 'AWS/SQS', 'ApproximateNumberOfMessagesVisible',
          {'Name': 'QueueName', 'Value': attr(logical, 'QueueName')}, 'Maximum')
alarm('EventBridgeDlqErrors', 'eventbridge-dlq-errors', 'AWS/Events', 'InvocationsFailedToBeSentToDLQ',
      {'Name': 'RuleName', 'Value': ref('IngressRule')})
template['Outputs'].update({
    'ProcessingFailureQueueUrl': {'Value': ref('ProcessingFailures')},
    'DeliveryFailureQueueUrl': {'Value': ref('DeliveryFailures')}
})
(root / 'infrastructure/risky-ssh.json').write_text(json.dumps(template, indent=2)+'\n')
