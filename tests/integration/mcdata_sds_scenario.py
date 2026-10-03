#!/usr/bin/env python3
"""Exercise standalone MCData SDS over the signalling control plane (TS 24.282 clause 9.2.2) and
the on-network disposition notifications (TS 24.282 clause 12.2), with the affiliation status
procedures (TS 24.282 clauses 8.2.3, 8.3.2.4, 8.3.2.5, 8.3.2.15), the transmission control of
TS 24.282 clause 11.1, ad hoc group SDS (TS 24.282 clause 24, clause 9.2.2.4.2 step 6A),
functional aliases (TS 24.282 clause 22), re-delivery of undelivered SDS (TS 24.282 clause
12.2.2.1 steps 5 and 6) and the MCData emergency alert (TS 24.282 clause 16.2).

Run against a fixture prepared with --mcdata (see add_mcdata_policy in
tools/prepare-prearranged-test.py). Check IDs match tests/mcdata/MCDATA_SDS_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
DELIVERED, READ, DELIVERED_AND_READ = 2, 3, 4


# ------------------------------------------------------------------------------
# Run the scenario: check AF, SD, AG, AD, FA, RD and EA and write the results file.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    domain = group.split('@', 1)[1]
    group_user = group.split(':', 1)[1].split('@', 1)[0]
    protected = bool(configs['client-a']['mcdata'].get('protect_payload'))
    checks, observations = [], {}
    result = dict(scenario='mcdata-standalone-sds', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the container of a role writes, or {} while it is missing or partly written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The status of every client and of the MCData server, attached to a failure.
    def snapshot():
        return {role: status(role) for role in roles + ['mcdata-server']}

    # ------------------------------------------------------------------------------
    # Run one mcx-client command in the container of a role.
    def command(role, text):
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Poll a predicate until it holds (the check passes) or the timeout expires (the scenario fails).
    def wait(label, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    # Record a passed check, or fail the scenario with a snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # The SDS messages a client received, or those that carry this text.
    def inbox(role, text=None):
        items = status(role).get('mcdata_inbox') or []
        if text is None:
            return items
        return [
            message for message in items if any(payload.get('text') == text for payload in message.get('payloads', []))
        ]

    # ------------------------------------------------------------------------------
    # The disposition notifications a client received for one message (TS 24.282 clause 12.2).
    def notifications(role, message_id):
        return [
            notification
            for notification in status(role).get('mcdata_notifications') or []
            if notification.get('message_id') == message_id
        ]

    # ------------------------------------------------------------------------------
    # The outcome of the last SDS a client sent.
    def last(role):
        return status(role).get('mcdata_last_result') or {}

    # ------------------------------------------------------------------------------
    # Send an SDS with a client command, wait until that new message is answered with the expected
    # status and warning text, and return its Message ID.
    def send(role, text, expect=202, warning=None, label=None):
        before = [record['message_id'] for record in status(role).get('mcdata_sent') or []]
        command(role, text)
        wait(
            label or f'{role}: {text[:40]} -> {expect}',
            lambda: (
                lambda sent: (
                    sent
                    and sent[-1]['message_id'] not in before
                    and last(role).get('message_id') == sent[-1]['message_id']
                    and last(role).get('status') == expect
                    and (warning is None or warning in last(role).get('warning', ''))
                )
            )(status(role).get('mcdata_sent') or []),
        )
        return (status(role).get('mcdata_sent') or [])[-1]['message_id']

    # ------------------------------------------------------------------------------
    # A text that no earlier message carried.
    def unique(label):
        return f'{label}-{secrets.token_hex(4)}'

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in roles
            ),
            90,
        )
        alertonly = f'sip:{group_user}-alertonly@{domain}'
        expected = {role: sorted([group, alertonly]) if role == 'client-d' else [group] for role in roles}
        wait(
            'server binds each MCData ID to its client and group',
            lambda: all(
                sorted(status('mcdata-server').get('users', {}).get(ids[role], {}).get('groups', [])) == expected[role]
                for role in roles
            ),
        )
        # AF-01 affiliation status determination (TS 24.282 clauses 8.2.3, 8.3.2.4, 8.3.2.5) and
        # implicit affiliation to configured groups (TS 24.282 clause 8.3.2.15).
        wait(
            'AF-01 every client holds an affiliation status subscription and its NOTIFY matches the server',
            lambda: all(
                status(role).get('mcdata_affiliation_subscribed')
                and sorted(status(role).get('mcdata_affiliations') or []) == expected[role]
                for role in roles
            ),
        )
        check(
            'AF-01 client-d is implicitly affiliated to its configured group and keeps it in its own PUBLISH',
            alertonly in status('client-d')['mcdata_affiliations'],
        )
        # AF-02 fetch the current state once (Expires 0).
        command('client-c', 'mcdata-affiliation-status fetch')
        wait(
            'AF-02 a fetch returns the current affiliations in one terminating NOTIFY',
            lambda: (
                (status('client-c').get('mcdata_affiliation_fetch') or {}).get('groups') == [group]
                and status('client-c')['mcdata_affiliation_fetch'].get('terminated')
            ),
        )
        # AF-03 another user's status needs authorisation (TS 24.282 clause 8.3.2.4 step 4).
        command('client-c', f'mcdata-affiliation-status fetch {ids["client-a"]}')
        wait(
            'AF-03 a subscription to another user\'s affiliation status is rejected with 403',
            lambda: (status('client-c').get('mcdata_affiliation_fetch') or {}).get('status') == 403,
        )
        # AF-04 de-subscription and a new subscription.
        command('client-c', 'mcdata-affiliation-status unsubscribe')
        wait(
            'AF-04 de-subscription ends with a terminating NOTIFY',
            lambda: not status('client-c').get('mcdata_affiliation_subscribed'),
        )
        command('client-c', 'mcdata-affiliation-status subscribe')
        wait(
            'AF-04 a new subscription reports the unchanged affiliation',
            lambda: (
                status('client-c').get('mcdata_affiliation_subscribed')
                and status('client-c').get('mcdata_affiliations') == [group]
                and status('client-c').get('mcdata_affiliated')
            ),
        )
        # AF-05 the NOTIFY caused by a PUBLISH carries its p-id (TS 24.282 clause 8.3.2.5 step 3d).
        command('client-d', 'mcdata-deaffiliate')
        wait(
            'AF-05 de-affiliation is reported by NOTIFY with no groups',
            lambda: (
                status('client-d').get('mcdata_affiliations') == [] and not status('client-d').get('mcdata_affiliated')
            ),
        )
        command('client-d', 'mcdata-affiliate')
        wait(
            'AF-05 re-affiliation is reported with the p-id of its PUBLISH',
            lambda: (
                status('client-d').get('mcdata_affiliations') == [group]
                and (lambda pid: pid.get('sent') and pid.get('sent') == pid.get('received'))(
                    status('client-d').get('mcdata_affiliation_p_id') or {}
                )
            ),
        )
        instance = status('mcdata-server')['instance_id']

        # SD-01 one-to-one text, rendered to the user.
        text = unique('hello-b')
        message = send('client-a', f'sds {ids["client-b"]} {text}', label='SD-01 one-to-one SDS accepted with 202')
        wait('SD-01 client-b receives the text from client-a', lambda: inbox('client-b', text))
        received = inbox('client-b', text)[0]
        check(
            'SD-01 message IDs, sender and user delivery preserved',
            received['message_id'] == message
            and received['from'] == ids['client-a']
            and received['delivered_to'] == 'user'
            and received['request_type'] == 'one-to-one-sds'
            and received['group'] == '',
        )
        check(
            'SD-01 no other client receives it',
            not any(inbox(role, text) for role in ['client-a', 'client-c', 'client-d']),
        )

        # SD-02 threading: a reply keeps the conversation and names the original message.
        reply = unique('reply-a')
        command('client-b', f'sds-reply {message} {reply}')
        wait(
            'SD-02 reply reaches client-a in the same conversation with InReplyTo',
            lambda: (
                inbox('client-a', reply)
                and inbox('client-a', reply)[0]['in_reply_to'] == message
                and inbox('client-a', reply)[0]['conversation_id'] == received['conversation_id']
            ),
        )

        # SD-03 delivery notification.
        message = send('client-a', f'sds delivery {ids["client-b"]} {unique("delivery")}')
        wait(
            'SD-03 DELIVERED notification returns to client-a from client-b',
            lambda: any(
                notification['type'] == DELIVERED and notification['from'] == ids['client-b']
                for notification in notifications('client-a', message)
            ),
        )

        # SD-04 read notification only after the display indication.
        text = unique('read')
        message = send('client-a', f'sds read {ids["client-b"]} {text}')
        wait('SD-04 message received', lambda: inbox('client-b', text))
        check('SD-04 no notification before display', holds(lambda: not notifications('client-a', message), 1))
        command('client-b', f'sds-display {message}')
        wait(
            'SD-04 READ notification after display',
            lambda: any(notification['type'] == READ for notification in notifications('client-a', message)),
        )

        # SD-05 delivery and read: display within TDU1 (TS 24.282 table F.2.3-1) gives one DELIVERED AND READ.
        text = unique('both-fast')
        message = send('client-a', f'sds both {ids["client-b"]} {text}')
        wait('SD-05 message received', lambda: inbox('client-b', text))
        command('client-b', f'sds-display {message}')
        wait(
            'SD-05 DELIVERED AND READ within TDU1',
            lambda: (
                [notification['type'] for notification in notifications('client-a', message)] == [DELIVERED_AND_READ]
            ),
        )
        # TDU1 expiry: DELIVERED first, READ after the later display.
        text = unique('both-slow')
        message = send('client-a', f'sds both {ids["client-b"]} {text}')
        wait(
            'SD-05 DELIVERED on TDU1 expiry',
            lambda: [notification['type'] for notification in notifications('client-a', message)] == [DELIVERED],
            10,
        )
        command('client-b', f'sds-display {message}')
        wait(
            'SD-05 READ after a late display',
            lambda: [notification['type'] for notification in notifications('client-a', message)] == [DELIVERED, READ],
        )

        # SD-06 application ID: known ID goes to the application, unknown is discarded.
        text = unique('app7')
        send('client-a', f'sds app=7 {ids["client-b"]} {text}')
        wait(
            'SD-06 known application ID delivered to the application',
            lambda: (
                inbox('client-b', text)
                and inbox('client-b', text)[0]['delivered_to'] == 'application'
                and inbox('client-b', text)[0]['application_id'] == 7
            ),
        )
        discarded = status('client-b').get('mcdata_discarded', 0)
        text = unique('app9')
        send('client-a', f'sds app=9 {ids["client-b"]} {text}')
        wait(
            'SD-06 unknown application ID discarded, not rendered',
            lambda: status('client-b').get('mcdata_discarded', 0) > discarded and not inbox('client-b', text),
        )

        # SD-11 application priority: requested by the sender, delivered as the used priority (V19.7.0).
        text = unique('priority')
        send('client-a', f'sds priority=5 {ids["client-b"]} {text}')
        wait(
            'SD-11 one-to-one SDS delivered with <used-priority> 5',
            lambda: inbox('client-b', text) and inbox('client-b', text)[0]['used_priority'] == 5,
        )
        text = unique('group-priority')
        send('client-a', f'sds-group priority=3 {group} {text}')
        wait(
            'SD-11 group SDS delivered with <used-priority> 3',
            lambda: all(
                inbox(role, text) and inbox(role, text)[0]['used_priority'] == 3
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        check('SD-11 no used priority without a request', inbox('client-b')[0]['used_priority'] is None)

        # SD-07 one-to-one rejections (TS 24.282 clauses 11.1, 9.2.2.3 and 9.2.2.4).
        send(
            'client-d',
            f'sds {ids["client-a"]} {unique("d")}',
            403,
            '200',
            'SD-07 user without <allow-transmit-data> rejected with 200',
        )
        send(
            'client-a', f'sds {ids["client-b"]} ' + 'x' * 350, 403, '202', 'SD-07 over <MaxData1To1> rejected with 202'
        )
        send(
            'client-a',
            f'sds {ids["client-d"]} {unique("d")}',
            403,
            '229',
            'SD-07 target outside <One-to-One-Communication> rejected with 229',
        )
        send(
            'client-c',
            f'sds {ids["client-a"]} ' + 'x' * 1100,
            403,
            '203',
            'SD-07 over the signalling-plane limit rejected with 203',
        )
        send(
            'client-c',
            f'sds {ids["client-a"]} ' + 'x' * 600,
            403,
            '218',
            'SD-07 over the one-to-one SDS size rejected with 218',
        )
        send(
            'client-c',
            f'sds {ids["client-b"]} {unique("c")}',
            403,
            '230',
            'SD-07 sender outside the target incoming list rejected with 230',
        )
        send(
            'client-c', f'sds {ids["client-c"]} {unique("self")}', 403, '204', 'SD-07 self as target rejected with 204'
        )

        # SD-08 group SDS to affiliated members with delivery notifications.
        text = unique('group')
        message = send('client-a', f'sds-group delivery {group} {text}', label='SD-08 group SDS accepted with 202')
        wait(
            'SD-08 every other affiliated member receives it with the group identity',
            lambda: all(
                inbox(role, text) and inbox(role, text)[0]['group'] == group
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        check('SD-08 the sender does not receive its own group message', not inbox('client-a', text))
        wait(
            'SD-08 a DELIVERED notification from each recipient, naming the group',
            lambda: (
                {
                    notification['from']
                    for notification in notifications('client-a', message)
                    if notification['type'] == DELIVERED and notification['group'] == group
                }
                == {ids['client-b'], ids['client-c'], ids['client-d']}
            ),
        )
        check(
            'AG-01 all three arrive in one aggregated notification once every recipient reported (12.2.3 step 15c-iv)',
            all(notification.get('aggregated') == 3 for notification in notifications('client-a', message))
            and len(notifications('client-a', message)) == 3,
        )
        # A group reply goes back to the group.
        reply = unique('group-reply')
        command('client-b', f'sds-reply {message} {reply}')
        wait(
            'SD-08 a group reply reaches the group in the same conversation',
            lambda: (
                inbox('client-a', reply)
                and inbox('client-a', reply)[0]['in_reply_to'] == message
                and inbox('client-a', reply)[0]['group'] == group
            ),
        )
        # AG-02 read requested: two members read, the third does not; TDC1 (TS 24.282 table
        # F.2.2-1) expiry sends the aggregate, and the late notification is relayed on its own
        # (TS 24.282 clause 12.2.3 steps 15c-iii and 15d).
        text = unique('aggregate-read')
        message = send(
            'client-a', f'sds-group read {group} {text}', label='AG-02 group SDS requesting read accepted with 202'
        )
        wait(
            'AG-02 every other affiliated member receives it',
            lambda: all(inbox(role, text) for role in ['client-b', 'client-c', 'client-d']),
        )
        command('client-b', f'sds-display {message}')
        command('client-d', f'sds-display {message}')
        check(
            'AG-02 READ notifications are held while TDC1 runs',
            holds(lambda: not notifications('client-a', message), 1),
        )
        wait(
            'AG-02 TDC1 expiry sends the two READ notifications in one aggregate',
            lambda: (
                sorted(
                    (notification['from'], notification['type'], notification.get('aggregated'))
                    for notification in notifications('client-a', message)
                )
                == sorted([(ids['client-b'], READ, 2), (ids['client-d'], READ, 2)])
            ),
            10,
        )
        command('client-c', f'sds-display {message}')
        wait(
            'AG-02 a notification after the aggregate is relayed individually with the notifier as calling user',
            lambda: any(
                notification['from'] == ids['client-c']
                and notification['type'] == READ
                and notification.get('aggregated') == 1
                for notification in notifications('client-a', message)
            ),
        )

        # SD-09 a de-affiliated member receives nothing.
        command('client-d', 'mcdata-deaffiliate')
        wait(
            'SD-09 client-d de-affiliated',
            lambda: (
                not status('client-d').get('mcdata_affiliated')
                and status('mcdata-server').get('users', {}).get(ids['client-d'], {}).get('groups') == []
            ),
        )
        text = unique('after-deaffiliation')
        send('client-a', f'sds-group {group} {text}')
        wait('SD-09 affiliated members receive', lambda: inbox('client-b', text) and inbox('client-c', text))
        check('SD-09 the de-affiliated member does not', holds(lambda: not inbox('client-d', text), 1))

        # SD-10 group rejections (TS 24.282 clause 9.2.2.4.2 step 6). With end-to-end protection
        # (--protected) the client holds no GMK for these groups and refuses to send.
        for suffix, code, warning, label in [
            ('nosuch', 404, '163', 'SD-10 unknown group rejected with 404/163'),
            ('parallel', 403, '116', 'SD-10 group without the sender as MCData member rejected with 116'),
            ('nosds', 403, '206', 'SD-10 group with SDS not allowed rejected with 206'),
            ('nosupport', 488, '207', 'SD-10 group without the SDS enabler rejected with 488/207'),
            ('preconf', 403, '167', 'SD-10 preconfigured-use-only group rejected with 167'),
            ('regrouped', 403, '148', 'SD-10 regrouped group rejected with 148'),
        ]:
            target = f'sip:{group_user}-{suffix}@{domain}'
            if protected:
                command('client-a', f'sds-group {target} {unique(suffix)}')
                wait(
                    f'SD-10 {suffix}: the client refuses to send without a group key for {target}',
                    lambda target=target: status('client-a').get('last_error') == 'no active group key for ' + target,
                )
            else:
                send('client-a', f'sds-group {target} {unique(suffix)}', code, warning, label)
        send(
            'client-c',
            f'sds-group {group} {unique("c")}',
            403,
            '201',
            'SD-10 sender without transmit permission on the group rejected with 201',
        )
        send(
            'client-a',
            f'sds-group {group} ' + 'x' * 900,
            403,
            '208',
            'SD-10 over the per-request group limit rejected with 208',
        )
        send(
            'client-a', f'sds-group {group} ' + 'x' * 500, 403, '217', 'SD-10 over the group SDS size rejected with 217'
        )
        send(
            'client-d',
            f'sds-group {group} {unique("d")}',
            403,
            '200',
            'SD-10 user without <allow-transmit-data> rejected with 200',
        )
        command('client-b', 'mcdata-deaffiliate')
        wait('SD-10 client-b de-affiliated', lambda: not status('client-b').get('mcdata_affiliated'))
        send('client-b', f'sds-group {group} {unique("b")}', 403, '120', 'SD-10 unaffiliated sender rejected with 120')
        command('client-c', 'mcdata-deaffiliate')
        wait('SD-10 client-c de-affiliated', lambda: not status('client-c').get('mcdata_affiliated'))
        send(
            'client-a',
            f'sds-group {group} {unique("alone")}',
            403,
            '198',
            'SD-10 no other affiliated member rejected with 198',
        )
        for role in ['client-b', 'client-c', 'client-d']:
            command(role, 'mcdata-affiliate')
        wait('SD-10 members re-affiliated', lambda: all(status(role).get('mcdata_affiliated') for role in roles))

        # AD-01 ad hoc group SDS to a participant list, with delivery notifications
        # (TS 24.282 clause 9.2.2.4.2 step 6A).
        text = unique('adhoc-list')
        message = send(
            'client-a',
            f'sds-adhoc delivery {ids["client-b"]},{ids["client-c"]} {text}',
            label='AD-01 ad hoc group SDS accepted with 202',
        )
        adhoc = last('client-a').get('group', '')
        check('AD-01 the 202 names a server-generated ad hoc group identity', adhoc.startswith('sip:adhoc-'))
        wait(
            'AD-01 the server records the initiator and participants as ad hoc group members',
            lambda: (
                set((status('mcdata-server').get('adhoc_groups') or {}).get(adhoc, []))
                == {ids['client-a'], ids['client-b'], ids['client-c']}
            ),
        )
        wait(
            'AD-01 each listed participant receives it with the ad hoc group identity',
            lambda: all(
                inbox(role, text)
                and inbox(role, text)[0]['group'] == adhoc
                and inbox(role, text)[0]['request_type'] == 'ad-hoc-group-sds'
                for role in ['client-b', 'client-c']
            ),
        )
        check('AD-01 users not listed receive nothing', not inbox('client-d', text) and not inbox('client-a', text))
        wait(
            'AD-02 a DELIVERED notification from each participant naming the ad hoc group',
            lambda: (
                {
                    notification['from']
                    for notification in notifications('client-a', message)
                    if notification['type'] == DELIVERED and notification['group'] == adhoc
                }
                == {ids['client-b'], ids['client-c']}
            ),
        )
        # AD-03 a reply goes to the same ad hoc group in the same conversation.
        reply = unique('adhoc-reply')
        command('client-b', f'sds-reply {message} {reply}')
        wait(
            'AD-03 a reply reaches the other ad hoc group members',
            lambda: all(
                inbox(role, reply)
                and inbox(role, reply)[0]['group'] == adhoc
                and inbox(role, reply)[0]['in_reply_to'] == message
                for role in ['client-a', 'client-c']
            ),
        )
        check('AD-03 the replier does not receive its own reply', not inbox('client-b', reply))
        # AD-04 a follow-up addressed to the ad hoc group identity.
        text = unique('adhoc-followup')
        send(
            'client-a', f'sds-adhoc group={adhoc} {text}', label='AD-04 follow-up to the ad hoc group identity accepted'
        )
        wait(
            'AD-04 the follow-up reaches the ad hoc group members',
            lambda: all(
                inbox(role, text) and inbox(role, text)[0]['group'] == adhoc for role in ['client-b', 'client-c']
            ),
        )
        # AD-05 participants from criteria; client-d is excluded for lack of participation permission.
        text = unique('adhoc-criteria')
        send(
            'client-a',
            f'sds-adhoc criteria=affiliated:{group} {text}',
            label='AD-05 ad hoc group SDS by criteria accepted',
        )
        second = last('client-a').get('group', '')
        wait(
            'AD-05 users meeting the criteria receive it in a new ad hoc group',
            lambda: all(
                inbox(role, text) and inbox(role, text)[0]['group'] == second for role in ['client-b', 'client-c']
            ),
        )
        check('AD-05 a new ad hoc group identity was generated', second.startswith('sip:adhoc-') and second != adhoc)
        check(
            'AD-05 a user without <allow-adhoc-group-data-comn-participation> is excluded',
            holds(lambda: not inbox('client-d', text), 1),
        )
        # AD-06 a listed participant without participation permission is skipped.
        text = unique('adhoc-skip')
        send(
            'client-a',
            f'sds-adhoc {ids["client-b"]},{ids["client-d"]} {text}',
            label='AD-06 list with a non-participant accepted',
        )
        wait('AD-06 the permitted participant receives it', lambda: inbox('client-b', text))
        check('AD-06 the non-participant does not', holds(lambda: not inbox('client-d', text), 1))
        # AD-07 rejections (TS 24.282 clause 24 authorisation; warning texts of TS 24.282 table 4.9.2-2).
        send(
            'client-c',
            f'sds-adhoc {ids["client-a"]},{ids["client-b"]} {unique("c")}',
            403,
            '238',
            'AD-07 sender without <allow-adhoc-group-data-comn> rejected with 238',
        )
        send(
            'client-a',
            f'sds-adhoc {ids["client-b"]},{ids["client-c"]},{ids["client-d"]},sip:ghost.mcdata@{domain} {unique("m")}',
            403,
            '242',
            'AD-07 more participants than the limit rejected with 242',
        )
        send(
            'client-a',
            f'sds-adhoc {ids["client-d"]} {unique("d")}',
            403,
            '241',
            'AD-07 only non-participants rejected with 241',
        )
        send(
            'client-a',
            f'sds-adhoc criteria=affiliated:sip:{group_user}-nosds@{domain} {unique("n")}',
            403,
            '240',
            'AD-07 criteria met by nobody rejected with 240',
        )
        send(
            'client-a',
            f'sds-adhoc criteria=nearby:1km {unique("v")}',
            403,
            '240',
            'AD-07 unknown criteria rejected with 240',
        )
        send(
            'client-a',
            f'sds-adhoc group=sip:adhoc-unknown@{domain} {unique("u")}',
            403,
            '240',
            'AD-07 unknown ad hoc group identity rejected with 240',
        )

        # FA-01 functional alias activation, limit, take-over and ownership
        # (TS 24.282 clauses 22.2.2.2.3, 22.2.2.3.3).
        desk, medic, reserve = (f'sip:{name}.fa@{domain}' for name in ('desk', 'medic', 'reserve'))

        # ------------------------------------------------------------------------------
        # The functional aliases the server holds, with the users that activated them.
        def aliases():
            return status('mcdata-server').get('functional_aliases') or {}

        # ------------------------------------------------------------------------------
        # Run a functional alias command and wait for the expected answer to that action.
        def fa(role, text, expect):
            command(role, text)
            wait(
                f'FA {role}: {text} -> {expect}',
                lambda: (
                    (status(role).get('mcdata_fa_last_result') or {}).get('status') == expect
                    and (status(role).get('mcdata_fa_last_result') or {}).get('action') == text.split()[1]
                ),
            )

        fa('client-a', f'mcdata-fa activate {desk}', 200)
        wait('FA-01 client-a holds desk', lambda: aliases().get(desk) == [ids['client-a']])
        fa('client-b', f'mcdata-fa activate {desk}', 403)
        check(
            'FA-01 the activation limit rejects a second activation without take-over',
            aliases().get(desk) == [ids['client-a']],
        )
        fa('client-b', f'mcdata-fa takeover {desk}', 200)
        wait(
            'FA-01 take-over by an authorised user replaces the holder',
            lambda: aliases().get(desk) == [ids['client-b']],
        )
        fa('client-c', f'mcdata-fa activate {desk}', 403)
        check('FA-01 a user outside <mcdata-user-list> cannot activate', aliases().get(desk) == [ids['client-b']])
        fa('client-c', f'mcdata-fa activate sip:nobody.fa@{domain}', 403)
        fa('client-c', f'mcdata-fa activate {medic}', 200)
        fa('client-d', f'mcdata-fa activate {medic}', 200)
        wait(
            'FA-01 two users hold medic within its limit of two',
            lambda: set(aliases().get(medic, [])) == {ids['client-c'], ids['client-d']},
        )

        # FA-02 SDS to a functional alias: 300 Multiple Choices, then a new request to the selected user.
        text = unique('to-medic')
        before = [record['message_id'] for record in status('client-c').get('mcdata_sent') or []]
        command('client-c', f'sds-fa {medic} {text}')
        wait(
            'FA-02 the SDS to the alias is redirected with 300',
            lambda: any(
                record['status'] == 300 and record['message_id'] not in before
                for record in status('client-c').get('mcdata_sent') or []
            ),
        )
        wait(
            'FA-02 client-d receives it with <called-functional-alias-URI>',
            lambda: (
                inbox('client-d', text)
                and inbox('client-d', text)[0]['called_functional_alias'] == medic
                and inbox('client-d', text)[0]['from'] == ids['client-c']
            ),
        )
        wait(
            'FA-02 the follow-up request was accepted with 202',
            lambda: any(
                record['status'] == 202 and record['called_alias'] == medic
                for record in status('client-c').get('mcdata_sent') or []
            ),
        )
        # FA-03 an alias with no active user; an alias target is subject to <One-to-One-Communication>
        # (TS 24.282 clause 11.1 step 1A).
        send(
            'client-c',
            f'sds-fa {reserve} {unique("r")}',
            403,
            '145',
            'FA-03 alias with no activated user rejected with 145',
        )
        send(
            'client-a',
            f'sds-fa {desk} {unique("a")}',
            403,
            '229',
            'FA-03 alias outside the sender one-to-one list rejected with 229',
        )

        # FA-04 presentation of the sender's alias only while it is active (TS 24.282 clause 9.2.2.3.1 step 12A).
        command('client-b', f'mcdata-fa use {desk}')
        text = unique('from-desk')
        send('client-b', f'sds {ids["client-a"]} {text}', label='FA-04 SDS from the desk holder accepted')
        wait(
            'FA-04 the recipient sees the active functional alias',
            lambda: inbox('client-a', text) and inbox('client-a', text)[0]['functional_alias'] == desk,
        )
        command('client-a', f'mcdata-fa use {desk}')  # client-a still believes it holds desk (no status NOTIFY)
        text = unique('stale-desk')
        send('client-a', f'sds {ids["client-b"]} {text}', label='FA-04 SDS presenting a taken-over alias accepted')
        wait(
            'FA-04 the server removes an alias the sender no longer holds',
            lambda: inbox('client-b', text) and inbox('client-b', text)[0]['functional_alias'] == '',
        )

        # FA-05 an ad hoc participant list naming an alias (TS 24.282 clause 9.2.2.4.2 step 6A b-ii).
        text = unique('adhoc-medic')
        send('client-a', f'sds-adhoc {medic} {text}', label='FA-05 ad hoc group SDS to an alias accepted')
        wait(
            'FA-05 an activated user receives it naming the alias',
            lambda: inbox('client-c', text) and inbox('client-c', text)[0]['called_functional_alias'] == medic,
        )
        check(
            'FA-05 an activated user without ad hoc participation permission is skipped',
            holds(lambda: not inbox('client-d', text), 1),
        )
        send(
            'client-a',
            f'sds-adhoc {reserve} {unique("r")}',
            403,
            '145',
            'FA-05 ad hoc alias with no activated user rejected with 145',
        )

        # FA-06 deactivation: an empty set is Expires 0.
        fa('client-c', f'mcdata-fa deactivate {medic}', 200)
        wait('FA-06 client-c no longer holds medic', lambda: aliases().get(medic) == [ids['client-d']])

        # ------------------------------------------------------------------------------
        # One of the MCData server's counters.
        def counter(name):
            return (status('mcdata-server').get('counters') or {}).get(name, 0)

        # ------------------------------------------------------------------------------
        # The entries the server holds for re-delivery of one message.
        def stored(message_id):
            return [
                entry
                for entry in status('mcdata-server').get('stored_for_redelivery') or []
                if entry['message_id'] == message_id
            ]

        # ------------------------------------------------------------------------------
        # The UNDELIVERED reports a client sent for one message.
        def undelivered(role, message_id):
            return [
                report for report in status(role).get('mcdata_undelivered') or [] if report['message_id'] == message_id
            ]

        # RD-01 a client without storage reports UNDELIVERED; the participating function stores the
        # message and re-delivers it at TDP1 expiry (TS 24.282 clause 12.2.2.1 steps 5 and 6, table
        # F.2.1-1).
        command('client-c', 'mcdata-storage full')
        redelivered = counter('sds_redelivered')
        text = unique('redeliver')
        message = send(
            'client-a',
            f'sds delivery {ids["client-c"]} {text}',
            label='RD-01 SDS to a client without storage accepted with 202',
        )
        wait(
            'RD-01 client-c reports UNDELIVERED and does not deliver the message',
            lambda: undelivered('client-c', message) and not inbox('client-c', text),
        )
        wait(
            'RD-01 the server stores the message with TDP1 running',
            lambda: stored(message) and stored(message)[0]['attempts'] == 0,
        )
        check('RD-01 UNDELIVERED is not sent on to the originator', not notifications('client-a', message))
        wait(
            'RD-02 TDP1 expiry re-delivers the stored message, which is again undelivered',
            lambda: (
                counter('sds_redelivered') > redelivered
                and len(undelivered('client-c', message)) >= 2
                and stored(message)
                and stored(message)[0]['attempts'] == 1
            ),
            10,
        )
        command('client-c', 'mcdata-storage unlimited')
        wait(
            'RD-02 the next re-delivery reaches the user unchanged',
            lambda: inbox('client-c', text) and inbox('client-c', text)[0]['message_id'] == message,
            10,
        )
        wait(
            'RD-02 the DELIVERED notification reaches the originator and ends the storage',
            lambda: (
                any(
                    notification['type'] == DELIVERED and notification['from'] == ids['client-c']
                    for notification in notifications('client-a', message)
                )
                and not stored(message)
            ),
        )
        check(
            'RD-02 the originator never sees UNDELIVERED',
            all(notification['type'] != 1 for notification in notifications('client-a', message)),
        )
        # RD-03 group SDS: re-delivery to one member is abandoned after the attempt limit.
        command('client-c', 'mcdata-storage full')
        abandoned = counter('redelivery_abandoned')
        text = unique('abandon')
        message = send('client-a', f'sds-group delivery {group} {text}', label='RD-03 group SDS accepted with 202')
        wait(
            'RD-03 the other members deliver it',
            lambda: (
                {notification['from'] for notification in notifications('client-a', message)}
                >= {ids['client-b'], ids['client-d']}
            ),
        )
        wait(
            'RD-03 after the attempt limit the stored message is discarded',
            lambda: (
                counter('redelivery_abandoned') > abandoned
                and not stored(message)
                and len(undelivered('client-c', message)) == 3
            ),
            15,
        )
        check(
            'RD-03 client-c never delivered it and the originator got no notification from client-c',
            not inbox('client-c', text)
            and not any(notification['from'] == ids['client-c'] for notification in notifications('client-a', message)),
        )
        command('client-c', 'mcdata-storage unlimited')

        # ------------------------------------------------------------------------------
        # The outcome of the last emergency alert request of a client.
        def alert_result(role):
            return status(role).get('mcdata_alert_last_result') or {}

        # ------------------------------------------------------------------------------
        # The emergency alerts of the group a client was told of, by originator.
        def alerts(role):
            return (status(role).get('mcdata_alerts_received') or {}).get(group, {})

        # ------------------------------------------------------------------------------
        # Send or cancel an emergency alert and wait for the expected answer and warning text.
        def alert(role, text, expect, label, warning=None):
            command(role, text)
            wait(
                label,
                lambda: (
                    alert_result(role).get('status') == expect
                    and (warning is None or warning in alert_result(role).get('warning', ''))
                    and alert_result(role).get('action') == ('cancel' if ' cancel' in text else 'alert')
                ),
            )

        # EA-01 MCData emergency alert to the group (TS 24.282 clauses 16.2.1.1, 16.2.3.1).
        alert('client-a', 'mcdata-alert', 200, 'EA-01 emergency alert accepted with 200')
        wait(
            'EA-01 the sender reaches MDEA 3 and the MCData emergency state',
            lambda: (
                status('client-a').get('mcdata_alert_state', '').startswith('MDEA 3')
                and status('client-a').get('mcdata_emergency')
            ),
        )
        wait(
            'EA-01 a receipt with <alert-ind-rcvd> reaches the sender',
            lambda: any(
                receipt['group'] == group and receipt['alert_ind']
                for receipt in status('client-a').get('mcdata_alert_receipts') or []
            ),
        )
        wait(
            'EA-01 every other affiliated member is notified with the originator, organisation and location',
            lambda: all(
                alerts(role).get(ids['client-a'], {}).get('organization') == 'Alpha Fire'
                and alerts(role)[ids['client-a']].get('latitude') == 1
                and alerts(role)[ids['client-a']].get('longitude') == 2
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        wait(
            'EA-01 the server records the outstanding alert',
            lambda: (status('mcdata-server').get('emergency_alerts') or {}).get(group) == [ids['client-a']],
        )
        # EA-02 late alert to a newly affiliated member (TS 24.282 clause 16.2.3.3).
        count = alerts('client-c')[ids['client-a']]['count']
        command('client-c', 'mcdata-deaffiliate')
        wait('EA-02 client-c de-affiliated', lambda: not status('client-c').get('mcdata_affiliated'))
        command('client-c', 'mcdata-affiliate')
        wait(
            'EA-02 a re-affiliating member receives the outstanding alert again',
            lambda: alerts('client-c').get(ids['client-a'], {}).get('count', 0) > count,
        )
        # EA-03 the originator cancels its own alert.
        alert('client-a', 'mcdata-alert cancel', 200, 'EA-03 cancellation accepted with 200')
        wait(
            'EA-03 the receipt returns the sender to MDEA 1 and clears the emergency state',
            lambda: (
                status('client-a').get('mcdata_alert_state', '').startswith('MDEA 1')
                and not status('client-a').get('mcdata_emergency')
            ),
        )
        wait(
            'EA-03 the other members see the alert cancelled',
            lambda: (
                all(ids['client-a'] not in alerts(role) for role in ['client-b', 'client-c', 'client-d'])
                and not (status('mcdata-server').get('emergency_alerts') or {}).get(group)
            ),
        )
        # EA-04 another authorised user cancels the alert of client-a (<originated-by>).
        alert('client-a', 'mcdata-alert', 200, 'EA-04 client-a alerts again')
        wait('EA-04 client-d is notified', lambda: ids['client-a'] in alerts('client-d'))
        alert('client-d', f'mcdata-alert cancel {ids["client-a"]}', 200, 'EA-04 client-d cancels the alert of client-a')
        wait(
            'EA-04 the originator is told and returns to MDEA 1',
            lambda: (
                status('client-a').get('mcdata_alert_state', '').startswith('MDEA 1')
                and not status('client-a').get('mcdata_emergency')
            ),
        )
        wait('EA-04 the other members see it cancelled', lambda: ids['client-a'] not in alerts('client-b'))
        # EA-05 rejections (TS 24.282 clauses 6.3.7.2.1, 6.3.7.2.2).
        alert(
            'client-c',
            'mcdata-alert',
            403,
            'EA-05 a user without <allow-activate-emergency-alert> is rejected with 403',
        )
        check('EA-05 the rejection carries <alert-ind> false', alert_result('client-c').get('alert_ind') is False)
        alert('client-b', 'mcdata-alert', 403, 'EA-05 a group outside the dedicated <EmergencyAlert> group is rejected')
        alert(
            'client-a',
            f'mcdata-alert group=sip:{group_user}-nosupport@{domain}',
            403,
            'EA-05 a group without <mcdata-allow-emergency-alert> is rejected',
        )
        alert(
            'client-a',
            f'mcdata-alert group=sip:{group_user}-preconf@{domain}',
            403,
            'EA-05 a preconfigured-use-only group is rejected with 168',
            '168',
        )
        alert(
            'client-a',
            f'mcdata-alert group=sip:{group_user}-alertonly@{domain}',
            403,
            'EA-05 a non-member is rejected with 120',
            '120',
        )
        alert(
            'client-c', 'mcdata-alert cancel', 403, 'EA-05 a user without <allow-cancel-emergency-alert> cannot cancel'
        )
        check(
            'EA-05 the cancellation rejection carries <alert-ind> true',
            alert_result('client-c').get('alert_ind') is True,
        )
        # EA-06 implicit affiliation of an eligible sender (TS 24.282 clause 16.2.3.1 step 4b-i).
        nosds = f'sip:{group_user}-nosds@{domain}'
        alert('client-b', f'mcdata-alert group={nosds}', 200, 'EA-06 client-b alerts on its dedicated group')
        wait(
            'EA-06 the unaffiliated member is implicitly affiliated',
            lambda: nosds in status('mcdata-server').get('users', {}).get(ids['client-b'], {}).get('groups', []),
        )
        wait(
            'EA-06 the implicit affiliation is reported to the client by NOTIFY',
            lambda: nosds in (status('client-b').get('mcdata_affiliations') or []),
        )
        alert('client-b', f'mcdata-alert cancel group={nosds}', 403, 'EA-06 client-b has no cancel permission (403)')

        server = status('mcdata-server')
        observations['server_counters'] = server.get('counters')
        check('server instance unchanged', server['instance_id'] == instance)
        result['passed'] = True
    except (AssertionError, KeyError, IndexError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-sds-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
