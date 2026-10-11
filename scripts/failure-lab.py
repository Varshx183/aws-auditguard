#!/usr/bin/env python3
"""Invoke, inspect and replay ONLY a synthetic lab failure. Uses AWS CLI v2."""
import argparse
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path


def aws(*args):
    result = subprocess.run(['aws', *args, '--region', os.environ.get('AWS_REGION', 'us-east-1'),
                             '--output', 'json'], check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def invoke(function, event, asynchronous=False):
    with tempfile.TemporaryDirectory() as tmp:
        payload, response = Path(tmp) / 'event.json', Path(tmp) / 'response.json'
        payload.write_text(json.dumps(event))
        result = aws('lambda', 'invoke', '--function-name', function,
                     '--invocation-type', 'Event' if asynchronous else 'RequestResponse',
                     '--payload', 'fileb://' + str(payload), str(response))
        if result.get('FunctionError'):
            raise RuntimeError('Replay failed; message was not deleted. Inspect Lambda logs.')
        if asynchronous:
            if result.get('StatusCode') != 202:
                raise RuntimeError('Async invocation was not accepted')
        else:
            body = json.loads(response.read_text())
            if body.get('findingCount', 0) < 1:
                raise RuntimeError('Replay produced no finding; message was not deleted')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['invoke', 'inspect', 'replay'])
    parser.add_argument('--event-id', help='Required exact synthetic event ID for replay')
    args = parser.parse_args()
    if args.action == 'replay' and (not args.event_id or not args.event_id.startswith('auditguard-failure-test-')):
        parser.error('Replay requires --event-id auditguard-failure-test-... from the invoke step')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name',
                os.environ.get('DETECTION_STACK_NAME', 'aws-auditguard-detection'))['Stacks'][0]
    outputs = {o['OutputKey']: o['OutputValue'] for o in stack['Outputs']}
    function, queue = outputs['FunctionName'], outputs['ProcessingFailureQueueUrl']
    if args.action == 'invoke':
        config = aws('lambda', 'get-function-configuration', '--function-name', function)
        if config.get('Environment', {}).get('Variables', {}).get('ENABLE_FAILURE_SIMULATION') != 'true':
            raise RuntimeError('Deploy with enable_failure_demo=true first')
        event = json.loads((Path(__file__).resolve().parents[1] / 'examples/risky-ssh.json').read_text())
        event['auditguardFailureSimulation'] = True
        event['detail']['eventID'] = 'auditguard-failure-test-' + str(uuid.uuid4())
        invoke(function, event, asynchronous=True)
        print('Synthetic failure accepted. Event ID:', event['detail']['eventID'])
        print('Allow several minutes for retries, then run: python3 scripts/failure-lab.py inspect')
        return
    messages = aws('sqs', 'receive-message', '--queue-url', queue, '--max-number-of-messages', '10',
                   '--wait-time-seconds', '10', '--visibility-timeout', '120').get('Messages', [])
    found = False
    for message in messages:
        deleted = False
        try:
            record = json.loads(message['Body'])
            event = record.get('requestPayload', {})
            if not isinstance(event, dict):
                continue
            detail = event.get('detail', {})
            event_id = detail.get('eventID', '')
            if not (event.get('auditguardFailureSimulation') is True
                    and event_id.startswith('auditguard-failure-test-')):
                continue
            found = True
            print(json.dumps({'eventId': event_id, 'synthetic': True,
                              'condition': record.get('requestContext', {}).get('condition'),
                              'attempts': record.get('requestContext', {}).get('approximateInvokeCount')}, indent=2))
            if args.action == 'replay' and event_id == args.event_id:
                event.pop('auditguardFailureSimulation')
                invoke(function, event)
                aws('sqs', 'delete-message', '--queue-url', queue, '--receipt-handle', message['ReceiptHandle'])
                deleted = True
                print('Replay succeeded; synthetic message deleted. Confirm the synthetic alert email.')
        finally:
            if not deleted:
                aws('sqs', 'change-message-visibility', '--queue-url', queue,
                    '--receipt-handle', message['ReceiptHandle'], '--visibility-timeout', '0')
    if not found:
        print('No synthetic test record found in this batch. Retry after delivery; nothing was deleted.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.stderr.strip())
