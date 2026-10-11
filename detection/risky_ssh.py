"""Detect world-open SSH in CloudTrail ingress authorization requests.

Modification events use a read-only lookup to confirm rule direction and current state.
No EC2 mutation is performed. Each permission is evaluated separately
so unrelated ports and CIDRs cannot be combined into a false positive.
"""
import ipaddress
import json
import os


def items(value):
    if isinstance(value, dict):
        value = value.get('items', [])
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def world_cidr(value):
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen == 0
    except (ValueError, TypeError):
        return False


def allows_ssh(permission):
    protocol = str(permission.get('ipProtocol', '')).lower()
    if protocol == '-1':
        return True
    if protocol not in ('tcp', '6'):
        return False
    try:
        low, high = int(permission['fromPort']), int(permission['toPort'])
        return 0 <= low <= 22 <= high <= 65535
    except (KeyError, TypeError, ValueError):
        return False


def modification_request(detail):
    request = detail.get('requestParameters') or {}
    if not isinstance(request, dict):
        raise ValueError('Unsupported modification request shape')
    request = request.get('ModifySecurityGroupRulesRequest', request)
    if not isinstance(request, dict):
        raise ValueError('Unsupported modification request shape')
    group = request.get('GroupId', request.get('groupId'))
    rules = request.get('SecurityGroupRule', request.get('securityGroupRuleSet',
                        request.get('securityGroupRules', [])))
    if isinstance(rules, dict) and ('SecurityGroupRuleId' in rules or 'securityGroupRuleId' in rules):
        rules = [rules]
    ids = sorted({r.get('SecurityGroupRuleId', r.get('securityGroupRuleId'))
                  for r in items(rules)
                  if isinstance(r.get('SecurityGroupRuleId', r.get('securityGroupRuleId')), str)})
    if not group or not ids:
        raise ValueError('Modification event lacks group or rule IDs; preserve for investigation')
    return group, ids


def event_detail(event):
    if not isinstance(event, dict):
        return {}
    detail = event.get('detail', event)
    return detail if isinstance(detail, dict) else {}


def supported(detail):
    return (detail.get('eventSource') == 'ec2.amazonaws.com'
            and detail.get('eventName') in ('AuthorizeSecurityGroupIngress', 'ModifySecurityGroupRules')
            and not detail.get('errorCode') and not detail.get('errorMessage'))


def detect(event, current_rules=None):
    """Accept a raw CloudTrail event or its EventBridge envelope."""
    detail = event_detail(event)
    if not supported(detail):
        return []
    request = detail.get('requestParameters') or {}
    if not isinstance(request, dict):
        return []
    modified = detail.get('eventName') == 'ModifySecurityGroupRules'
    if modified:
        group, ids = modification_request(detail)
        if current_rules is None:
            raise ValueError('Modification detection requires current rule lookup')
        request = {'groupId': group}
        permissions = []
        for rule in current_rules:
            if (rule.get('SecurityGroupRuleId') not in ids or rule.get('GroupId') != group
                    or rule.get('IsEgress') is not False):
                continue
            permissions.append({
                'ipProtocol': rule.get('IpProtocol'), 'fromPort': rule.get('FromPort'),
                'toPort': rule.get('ToPort'), 'securityGroupRuleId': rule.get('SecurityGroupRuleId'),
                'ipRanges': [{'cidrIp': rule.get('CidrIpv4')}],
                'ipv6Ranges': [{'cidrIpv6': rule.get('CidrIpv6')}]})
    else:
        permissions = items(request.get('ipPermissions'))
        # Legacy single-permission EC2 request form.
        if not permissions and 'ipProtocol' in request:
            permissions = [dict(request, ipRanges={'items': [{'cidrIp': request.get('cidrIp')}]})]
    findings = []
    for permission in permissions:
        if not allows_ssh(permission):
            continue
        cidrs = [p.get('cidrIp') for p in items(permission.get('ipRanges'))]
        cidrs += [p.get('cidrIpv6') for p in items(permission.get('ipv6Ranges'))]
        for cidr in sorted({c for c in cidrs if isinstance(c, str) and world_cidr(c)}):
            identity = detail.get('userIdentity') or {}
            findings.append({
                'ruleId': 'AG-SSH-002' if modified else 'AG-SSH-001',
                'title': 'Security group ingress permits SSH from the entire internet',
                'eventId': detail.get('eventID'),
                'eventName': detail.get('eventName'),
                'evidenceBasis': 'current-rule-state' if modified else 'event-request',
                'securityGroupRuleId': permission.get('securityGroupRuleId'),
                'eventTime': detail.get('eventTime'),
                'region': detail.get('awsRegion'),
                'groupId': request.get('groupId'),
                'groupName': request.get('groupName'),
                'actorArn': identity.get('arn') if isinstance(identity, dict) else None,
                'cidr': cidr,
                'protocol': permission.get('ipProtocol'),
                'fromPort': permission.get('fromPort'),
                'toPort': permission.get('toPort'),
                'assessment': 'Risky rule change; actual host reachability is not established.'
            })
    return findings


def handler(event, context):
    detail = event_detail(event)
    current_rules = None
    if supported(detail) and detail.get('eventName') == 'ModifySecurityGroupRules':
        import boto3
        group, ids = modification_request(detail)
        current_rules = []
        paginator = boto3.client('ec2').get_paginator('describe_security_group_rules')
        for page in paginator.paginate(Filters=[{'Name': 'security-group-rule-id', 'Values': ids}]):
            current_rules.extend(page.get('SecurityGroupRules', []))
        unresolved = len(set(ids) - {r['SecurityGroupRuleId'] for r in current_rules})
        print(json.dumps({'lookupRuleCount': len(current_rules), 'unresolvedRuleCount': unresolved}))
    findings = detect(event, current_rules=current_rules)
    if findings:
        # Only explicitly enabled lab invocations can inject this synthetic failure.
        if (os.environ.get('ENABLE_FAILURE_SIMULATION') == 'true'
                and event.get('auditguardFailureSimulation') is True):
            raise RuntimeError('AuditGuard lab: simulated failure before SNS publish')
        import boto3
        # Publish errors propagate to asynchronous retries and the failure destination.
        boto3.client('sns').publish(
            TopicArn=os.environ['ALERT_TOPIC_ARN'],
            Subject='AuditGuard: world-open SSH rule detected',
            Message=json.dumps({'findings': findings}, indent=2))
    print(json.dumps({'eventName': detail.get('eventName'), 'findingCount': len(findings)}))
    return {'findingCount': len(findings)}
