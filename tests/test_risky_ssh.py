import copy
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from detection.risky_ssh import detect, handler


def permission(protocol='tcp', low=22, high=22, cidr='0.0.0.0/0', ipv6=False):
    return {'ipProtocol': protocol, 'fromPort': low, 'toPort': high,
            'ipv6Ranges' if ipv6 else 'ipRanges': {'items': [
                {'cidrIpv6' if ipv6 else 'cidrIp': cidr}]}}


def event(*permissions):
    return {'eventSource': 'ec2.amazonaws.com', 'eventName': 'AuthorizeSecurityGroupIngress',
            'eventID': 'synthetic-event', 'eventTime': '2026-10-11T12:00:00Z',
            'awsRegion': 'us-east-1', 'userIdentity': {'arn': 'synthetic-actor'},
            'requestParameters': {'groupId': 'sg-example', 'ipPermissions': {'items': list(permissions)}}}


class DetectionTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(len(detect(event(permission()))), 1)

    def test_ipv6(self):
        self.assertEqual(len(detect(event(permission(cidr='::/0', ipv6=True)))), 1)

    def test_port_range(self):
        self.assertEqual(len(detect(event(permission(low=0, high=65535)))), 1)

    def test_all_protocols_without_ports(self):
        p = permission(protocol='-1'); p.pop('fromPort'); p.pop('toPort')
        self.assertEqual(len(detect(event(p))), 1)

    def test_numeric_tcp(self):
        self.assertEqual(len(detect(event(permission(protocol=6, low='22', high='22')))), 1)

    def test_private_ssh(self):
        self.assertEqual(detect(event(permission(cidr='10.0.0.0/8'))), [])

    def test_public_web(self):
        self.assertEqual(detect(event(permission(low=443, high=443))), [])

    def test_udp_22(self):
        self.assertEqual(detect(event(permission(protocol='udp'))), [])

    def test_cross_permission_false_positive(self):
        self.assertEqual(detect(event(permission(cidr='10.0.0.0/8'), permission(low=443, high=443))), [])

    def test_mixed_permissions_only_flags_ssh(self):
        self.assertEqual(len(detect(event(permission(), permission(low=443, high=443)))), 1)

    def test_failed_api_call(self):
        e = event(permission()); e['errorCode'] = 'Client.UnauthorizedOperation'
        self.assertEqual(detect(e), [])

    def test_unrelated_api(self):
        e = event(permission()); e['eventName'] = 'RevokeSecurityGroupIngress'
        self.assertEqual(detect(e), [])

    def test_wrong_source(self):
        e = event(permission()); e['eventSource'] = 'example.amazonaws.com'
        self.assertEqual(detect(e), [])

    def test_eventbridge_envelope(self):
        self.assertEqual(len(detect({'detail': event(permission())})), 1)

    def test_legacy_request(self):
        e = event(); e['requestParameters'] = dict(permission(), cidrIp='0.0.0.0/0')
        self.assertEqual(len(detect(e)), 1)

    def test_malformed(self):
        for e in (None, [], {}, {'detail': None}, {'detail': []}):
            with self.subTest(event=e):
                self.assertEqual(detect(e), [])

    def test_bad_cidr_and_ports(self):
        for p in (permission(cidr='bad'), permission(low=None), permission(low=30, high=20)):
            with self.subTest(permission=p):
                self.assertEqual(detect(event(p)), [])

    def test_duplicate_cidr(self):
        p = permission(); p['ipRanges']['items'] *= 2
        self.assertEqual(len(detect(event(p))), 1)

    def test_no_input_mutation(self):
        e = event(permission()); before = copy.deepcopy(e); detect(e)
        self.assertEqual(e, before)

    def test_handler_publish(self):
        sns = Mock()
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda _: sns)}), \
                patch.dict(os.environ, {'ALERT_TOPIC_ARN': 'test-topic'}):
            self.assertEqual(handler(event(permission()), None), {'findingCount': 1})
        sns.publish.assert_called_once()
        self.assertEqual(sns.publish.call_args.kwargs['TopicArn'], 'test-topic')

    def test_handler_safe_event_no_publish(self):
        sns = Mock()
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda _: sns)}):
            self.assertEqual(handler(event(permission(cidr='10.0.0.0/8')), None), {'findingCount': 0})
        sns.publish.assert_not_called()

    def test_publish_failure_propagates(self):
        sns = Mock(); sns.publish.side_effect = RuntimeError('publish failed')
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda _: sns)}), \
                patch.dict(os.environ, {'ALERT_TOPIC_ARN': 'test-topic'}):
            with self.assertRaises(RuntimeError):
                handler(event(permission()), None)

    def test_deployable_code_matches_source(self):
        template = json.loads(Path('infrastructure/risky-ssh.json').read_text())
        code = template['Resources']['Detector']['Properties']['Code']['ZipFile']
        self.assertEqual(code, Path('detection/risky_ssh.py').read_text())


def modified_event():
    return {'eventSource': 'ec2.amazonaws.com', 'eventName': 'ModifySecurityGroupRules',
            'eventID': 'synthetic-modify', 'awsRegion': 'us-east-1',
            'requestParameters': {'ModifySecurityGroupRulesRequest': {
                'GroupId': 'sg-example', 'SecurityGroupRule': {
                    'SecurityGroupRuleId': 'sgr-example', 'SecurityGroupRule': {'CidrIpv4': '0.0.0.0/0'}}}}}


def current_rule(**updates):
    result = {'SecurityGroupRuleId': 'sgr-example', 'GroupId': 'sg-example',
              'IsEgress': False, 'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
              'CidrIpv4': '0.0.0.0/0'}
    result.update(updates)
    return result


class ModificationTests(unittest.TestCase):
    def test_partial_update_uses_current_state(self):
        result = detect(modified_event(), [current_rule()])
        self.assertEqual(result[0]['ruleId'], 'AG-SSH-002')
        self.assertEqual(result[0]['evidenceBasis'], 'current-rule-state')

    def test_egress_is_not_ingress(self):
        self.assertEqual(detect(modified_event(), [current_rule(IsEgress=True)]), [])

    def test_unresolved_direction_not_assumed(self):
        self.assertEqual(detect(modified_event(), [current_rule(IsEgress=None)]), [])

    def test_other_rule_is_not_attributed(self):
        self.assertEqual(detect(modified_event(), [current_rule(SecurityGroupRuleId='sgr-other')]), [])

    def test_other_group_is_not_attributed(self):
        self.assertEqual(detect(modified_event(), [current_rule(GroupId='sg-other')]), [])

    def test_private_current_state(self):
        self.assertEqual(detect(modified_event(), [current_rule(CidrIpv4='10.0.0.0/8')]), [])

    def test_deleted_rule(self):
        self.assertEqual(detect(modified_event(), []), [])

    def test_missing_lookup_rejected(self):
        with self.assertRaises(ValueError):
            detect(modified_event())

    def test_unknown_shape_not_silent(self):
        e = modified_event(); e['requestParameters'] = {}
        with self.assertRaises(ValueError):
            detect(e, [])

    def test_lowercase_container(self):
        e = modified_event(); e['requestParameters'] = {
            'groupId': 'sg-example', 'securityGroupRuleSet': {'items': [{'securityGroupRuleId': 'sgr-example'}]}}
        self.assertEqual(len(detect(e, [current_rule()])), 1)

    def test_multiple_uppercase_rules(self):
        e = modified_event(); e['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule'] = [
            {'SecurityGroupRuleId': 'sgr-example'}, {'SecurityGroupRuleId': 'sgr-other'}]
        self.assertEqual(len(detect(e, [current_rule(), current_rule(SecurityGroupRuleId='sgr-other', IsEgress=True)])), 1)

    def test_modify_ipv6(self):
        self.assertEqual(len(detect(modified_event(), [current_rule(CidrIpv4=None, CidrIpv6='::/0')])), 1)

    def test_handler_lookup_and_publish(self):
        ec2, sns = Mock(), Mock()
        ec2.get_paginator.return_value.paginate.return_value = [{'SecurityGroupRules': [current_rule()]}]
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda name: ec2 if name == 'ec2' else sns)}), patch.dict(os.environ, {'ALERT_TOPIC_ARN': 'test'}):
            self.assertEqual(handler(modified_event(), None), {'findingCount': 1})
        sns.publish.assert_called_once()

    def test_lookup_failure_propagates(self):
        ec2 = Mock(); ec2.get_paginator.side_effect = RuntimeError('access denied')
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda name: ec2)}):
            with self.assertRaises(RuntimeError):
                handler(modified_event(), None)

    def test_failed_modification_no_lookup(self):
        e = modified_event(); e['errorCode'] = 'Denied'
        self.assertEqual(handler(e, None), {'findingCount': 0})

    def test_failure_simulation_requires_enabled_flag(self):
        e = {'detail': event(permission()), 'auditguardFailureSimulation': True}
        with patch.dict(os.environ, {'ENABLE_FAILURE_SIMULATION': 'true'}):
            with self.assertRaisesRegex(RuntimeError, 'simulated failure'):
                handler(e, None)

    def test_failure_simulation_disabled_by_default(self):
        sns = Mock(); e = {'detail': event(permission()), 'auditguardFailureSimulation': True}
        with patch.dict(sys.modules, {'boto3': types.SimpleNamespace(client=lambda name: sns)}), patch.dict(os.environ, {'ENABLE_FAILURE_SIMULATION': 'false', 'ALERT_TOPIC_ARN': 'test'}):
            self.assertEqual(handler(e, None), {'findingCount': 1})
        sns.publish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
