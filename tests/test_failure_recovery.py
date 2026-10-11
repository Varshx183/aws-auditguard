import importlib.util
import json
import sys
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('failure_lab', 'scripts/failure-lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class FailureRecoveryTests(unittest.TestCase):
    def exercise(self, action, invoke_error=None, synthetic=True):
        event_id = 'auditguard-failure-test-example'
        event = {'auditguardFailureSimulation': synthetic, 'detail': {'eventID': event_id}}
        message = {'ReceiptHandle': 'receipt', 'Body': json.dumps({'requestPayload': event})}
        def response(*args):
            if args[:2] == ('cloudformation', 'describe-stacks'):
                return {'Stacks': [{'Outputs': [{'OutputKey': 'FunctionName', 'OutputValue': 'function'},
                                               {'OutputKey': 'ProcessingFailureQueueUrl', 'OutputValue': 'queue'}]}]}
            if args[:2] == ('sqs', 'receive-message'):
                return {'Messages': [message]}
            return {}
        client = Mock(side_effect=response)
        invocation = Mock(side_effect=invoke_error)
        with patch.object(lab, 'aws', client), patch.object(lab, 'invoke', invocation), \
                patch.object(sys, 'argv', ['failure-lab.py', action, '--event-id', event_id]):
            if invoke_error:
                with self.assertRaises(RuntimeError):
                    lab.main()
            else:
                lab.main()
        return client, invocation

    def test_inspection_never_deletes(self):
        client, invocation = self.exercise('inspect')
        self.assertFalse(any(c.args[:2] == ('sqs', 'delete-message') for c in client.call_args_list))
        invocation.assert_not_called()

    def test_replay_deletes_only_after_success(self):
        client, invocation = self.exercise('replay')
        invocation.assert_called_once()
        self.assertNotIn('auditguardFailureSimulation', invocation.call_args.args[1])
        self.assertTrue(any(c.args[:2] == ('sqs', 'delete-message') for c in client.call_args_list))

    def test_failed_replay_retains_message(self):
        client, invocation = self.exercise('replay', RuntimeError('SNS failure'))
        self.assertFalse(any(c.args[:2] == ('sqs', 'delete-message') for c in client.call_args_list))
        self.assertTrue(any(c.args[:2] == ('sqs', 'change-message-visibility') for c in client.call_args_list))

    def test_real_event_is_not_replayed_or_deleted(self):
        client, invocation = self.exercise('replay', synthetic=False)
        invocation.assert_not_called()
        self.assertFalse(any(c.args[:2] == ('sqs', 'delete-message') for c in client.call_args_list))
