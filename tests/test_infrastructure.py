import json
import unittest
from pathlib import Path


class DeploymentBoundaries(unittest.TestCase):
    def setUp(self):
        self.bootstrap = json.loads(Path('infrastructure/github-oidc.json').read_text())['Resources']
        self.detector = json.loads(Path('infrastructure/risky-ssh.json').read_text())['Resources']

    def test_oidc_trust_exact_branch_and_audience(self):
        trust = self.bootstrap['GitHubDeployRole']['Properties']['AssumeRolePolicyDocument']['Statement'][0]
        conditions = trust['Condition']['StringEquals']
        self.assertEqual(conditions['token.actions.githubusercontent.com:aud'], 'sts.amazonaws.com')
        self.assertEqual(conditions['token.actions.githubusercontent.com:sub'], {'Ref': 'GitHubOidcSubject'})
        parameter = json.loads(Path('infrastructure/github-oidc.json').read_text())['Parameters']['GitHubOidcSubject']
        self.assertEqual(parameter['Default'], 'repo:Varshx183@207301812/aws-auditguard@1413488585:ref:refs/heads/main')
        import re
        self.assertIsNotNone(re.fullmatch(parameter['AllowedPattern'], parameter['Default']))
        for invalid in ('repo:Varshx183/aws-auditguard:ref:refs/heads/main',
                        parameter['Default'].replace('/main', '/other'),
                        parameter['Default'].replace('@207301812', '@*')):
            self.assertIsNone(re.fullmatch(parameter['AllowedPattern'], invalid))

    def test_deployment_role_cannot_manage_iam(self):
        for role in ['GitHubDeployRole', 'CloudFormationRole']:
            statements = self.bootstrap[role]['Properties']['Policies'][0]['PolicyDocument']['Statement']
            for statement in statements:
                actions = statement['Action']
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action.startswith('iam:'):
                        self.assertEqual(action, 'iam:PassRole')
                        self.assertIn('iam:PassedToService', statement['Condition']['StringEquals'])
                        self.assertNotEqual(statement['Resource'], '*')

    def test_stack_updates_can_read_detection_template_summary(self):
        statements = self.bootstrap['GitHubDeployRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        matches = [s for s in statements if 'cloudformation:GetTemplateSummary' in
                   (s['Action'] if isinstance(s['Action'], list) else [s['Action']])]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['Resource'], {
            'Fn::Sub': 'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/aws-auditguard-detection/*'})

    def test_runtime_has_no_ec2_mutation(self):
        statements = self.bootstrap['RuntimeRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        for statement in statements:
            actions = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
            for action in actions:
                if action.startswith('ec2:'):
                    self.assertEqual(action, 'ec2:DescribeSecurityGroupRules')
                    self.assertIn('aws:RequestedRegion', statement['Condition']['StringEquals'])

    def test_separate_failure_destinations(self):
        target = self.detector['IngressRule']['Properties']['Targets'][0]
        self.assertEqual(target['DeadLetterConfig']['Arn']['Fn::GetAtt'][0], 'DeliveryFailures')
        destination = self.detector['AsyncFailureDestination']['Properties']['DestinationConfig']['OnFailure']
        self.assertEqual(destination['Destination']['Fn::GetAtt'][0], 'ProcessingFailures')

    def test_failure_simulation_default_off(self):
        template = json.loads(Path('infrastructure/risky-ssh.json').read_text())
        self.assertEqual(template['Parameters']['EnableFailureSimulation']['Default'], 'false')

    def test_processing_failure_health_alarm(self):
        alarm = self.detector['ProcessingFailuresAlarm']['Properties']
        self.assertEqual(alarm['MetricName'], 'ApproximateNumberOfMessagesVisible')
        self.assertEqual(alarm['AlarmActions'], [{'Ref': 'AlertTopicArn'}])

    def test_delivery_queue_policy_scoped_to_rule(self):
        statement = self.detector['DeliveryQueuePolicy']['Properties']['PolicyDocument']['Statement'][0]
        self.assertEqual(statement['Principal']['Service'], 'events.amazonaws.com')
        self.assertIn('${AWS::StackName}-ingress', statement['Condition']['ArnEquals']['aws:SourceArn']['Fn::Sub'])
