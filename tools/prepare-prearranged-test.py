#!/usr/bin/env python3
# Prepares the single-system lab: runs tools/provision.py on a copy of the lab description
# with four clients (client-a to client-d), then adds what the flags ask for to the generated
# configuration (the user profiles, group documents and service configuration the MCPTT,
# MCData and MCVideo servers and the clients read) and writes the lab's compose.json. It
# never starts containers. Lab provisioning only: the profiles and groups follow the user
# profile and group configuration of TS 24.484 and TS 24.481 and the procedures each lab
# exercises, named at each function.
#
# Specifications: TS 23.379 V19.11.0, TS 24.281 V19.6.0, TS 24.282 V19.7.0, TS 24.379 V19.7.0,
# TS 24.481 V19.3.0, TS 24.484 V19.6.0, TS 24.581 V19.2.0, TS 33.180 V19.4.0 (all Rel-19);
# TS 24.545, TS 24.229, TS 23.032 (cited only).
"""Prepare a separate four-client Compose lab; never starts containers."""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import lab_images

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------
def add_parallel_group(fixture, source):
    """Extend only the separately generated fixture, preserving its credentials: a second
    prearranged group of client-c and client-d, which both may select."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    first = site['groups'][0]['id']
    second = f"sip:{source['group_user']}-parallel@{source['domain']}"
    configs = {}
    for role in ['client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        config['mcptt']['allowed_groups'] = [first, second]
        path.write_text(json.dumps(config, indent=2) + '\n')
        configs[role] = config
    members = [config['mcptt']['user_id'] for config in configs.values()]
    site['groups'] = [group for group in site['groups'] if group['id'] != second]
    site['groups'].append(dict(id=second, members=members, protect_media=False, protect_floor=False))
    for user in site['users']:
        if user['mcptt_id'] in members and second not in user['groups']:
            user['groups'].append(second)
    site_file.write_text(json.dumps(site, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_private_call_policy(fixture, refresh=False):
    """Give each fixture user a different TS 24.484 private-call ruleset.

    client-a: all commencement modes and first-to-answer calls, restricted
              <PrivateCall> list (b, c); emergency private calls and alerts to
              anyone, with cancellation; both ambient listening types
    client-b: automatic and manual, no force auto answer, any target;
              emergency private calls to client-a only, no cancellation or alerts;
              locally initiated ambient listening only
    client-c: automatic commencement only, any target; accepts incoming
              private calls only from client-a (<IncomingPrivateCallList>)
    client-d: no private-call authorization and unable to be called
    """
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        client: json.loads((fixture / f'generated/{client}.json').read_text())['mcptt']['user_id']
        for client in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    policies = {
        ids['client-a']: dict(
            allow=True,
            automatic_commencement=True,
            manual_commencement=True,
            force_auto_answer=True,
            first_to_answer=True,
            targets=[ids['client-b'], ids['client-c']],
            emergency=True,
            emergency_any=True,
            emergency_cancel=True,
            alert=True,
            alert_any=True,
            alert_cancel=True,
            ambient_remote=True,
            ambient_local=True,
        ),
        ids['client-b']: dict(
            allow=True,
            automatic_commencement=True,
            manual_commencement=True,
            any_target=True,
            emergency=True,
            emergency_recipients=[ids['client-a']],
            ambient_local=True,
        ),
        ids['client-c']: dict(
            allow=True, automatic_commencement=True, any_target=True, incoming_from=[ids['client-a']]
        ),
        ids['client-d']: dict(allow=False, callable=False),
    }
    for user in site['users']:
        user.pop('private_call', None)
        user.pop('group_call', None)
        # client-a may remotely initiate a group call (TS 24.379 clause 10.1.5).
        if user['mcptt_id'] == ids['client-a']:
            user['group_call'] = dict(remote_init=True)
        if user['mcptt_id'] in policies:
            user['private_call'] = policies[user['mcptt_id']]
    # A preconfigured-use-only group (TS 24.379 clause 10.1.5.2.1 step 1A, clause 10.1.5.4 step 2A)
    # without client-a: its GMS serves the document to members only, so client-a's
    # request reaches the server (167), while member client-c refuses it itself.
    group = json.loads((fixture / 'generated/client-a.json').read_text())['mcptt']['group_id']
    preconf = group.replace('@', '-ric-preconf@')
    members = [ids['client-b'], ids['client-c'], ids['client-d']]
    site['groups'] = [existing for existing in site['groups'] if existing['id'] != preconf]
    site['groups'].append(
        dict(id=preconf, members=members, protect_media=False, protect_floor=False, preconfigured_use_only=True)
    )
    for user in site['users']:
        if user['mcptt_id'] in members and preconf not in user['groups']:
            user['groups'].append(preconf)
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    # Emergency private calls carry Resource-Priority (TS 24.379 clause 6.2.8.3.3).
    resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
    for role in ['mcptt-server', 'client-a', 'client-b', 'client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        cfg = json.loads(path.read_text())
        cfg['mcptt'].setdefault('resource_priority', resources)
        if role != 'mcptt-server':
            # Synthetic TS 23.032 encoded fields for the isolated simulator only.
            cfg['mcptt'].setdefault('emergency_location', dict(latitude=1, longitude=2))
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    server_file = fixture / 'generated/mcptt-server.json'
    server = json.loads(server_file.read_text())
    # Short setup and private call timers keep timeout scenarios bounded. With
    # refresh, the private call timer outlasts the 45 s refresh point of the
    # 90 s SIP session timer, and inactivity cannot end the call first.
    server['mcptt']['private_call'] = dict(
        setup_timeout_ms=5000,
        max_calls=1,
        inactivity_timeout_ms=120000 if refresh else 60000,
        maximum_duration_ms=70000 if refresh else 30000,
    )
    server_file.write_text(json.dumps(server, indent=2) + '\n')


# ------------------------------------------------------------------------------
def square(lat, lon, half):
    """A square polygon of [latitude, longitude] corners, half degrees either side of its centre."""
    return [[lat - half, lon - half], [lat - half, lon + half], [lat + half, lon + half], [lat + half, lon - half]]


# Location management (TS 24.379 clauses 13, 6.3.2.4): every client starts at its
# own position near 48 N 2 E; a zone north of them is a reporting trigger, one
# area further north-east is an emergency alert area, and one the group's
# geographic area.
LOCATION_ZONE = square(48.01, 2.0, 0.002)
LOCATION_HAZARD = square(48.05, 2.05, 0.003)
LOCATION_GROUP_AREA = square(48.02, 2.02, 0.003)


# ------------------------------------------------------------------------------
def add_location(fixture):
    """Location reporting, requests and areas (TS 24.379 clause 13, TS 24.282 clause 17,
    TS 24.281 clause 18): each client's location rights in its profile, the server's reporting
    configuration, alert and group areas, and each client's simulated position."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        client: json.loads((fixture / f'generated/{client}.json').read_text())['mcptt']['user_id']
        for client in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    rights = {
        ids['client-a']: dict(request=True, configure=True),
        ids['client-b']: dict(share_with=['*']),
        ids['client-c']: dict(share_with=[ids['client-b']]),
        ids['client-d']: dict(report=False),
    }
    for user in site['users']:
        if user['mcptt_id'] in rights:
            user['location'] = rights[user['mcptt_id']]
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    group = site['groups'][0]['id']
    server_file = fixture / 'generated/mcptt-server.json'
    server = json.loads(server_file.read_text())
    # The same reporting configuration from both participating functions: MCPTT
    # (TS 24.379 clause 13) and MCData (TS 24.282 clause 17).
    server['mcptt']['location'] = dict(
        configuration=dict(
            non_emergency=dict(coordinate=True, serving_ecgi=True, minimum_interval=1),
            emergency=dict(coordinate=True, minimum_interval=1),
            triggers=[
                dict(event='InitialLogOn'),
                dict(event='GroupCallNonEmergency'),
                dict(distance=250),
                dict(enter_area=dict(polygon=LOCATION_ZONE, inner_border=10)),
                dict(exit_area=dict(polygon=LOCATION_ZONE, outer_border=10)),
                dict(any_change='cell'),
            ],
            emergency_triggers=[dict(periodic=2)],
        ),
        max_age_ms=4000,
        wait_ms=4000,
        emergency_alert_areas=dict(hazard=dict(polygon=LOCATION_HAZARD)),
        group_areas={group: dict(polygon=LOCATION_GROUP_AREA)},
    )
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    data_file = fixture / 'generated/mcdata-server.json'
    if data_file.exists():
        data_server = json.loads(data_file.read_text())
        mcdata_group = (
            json.loads((fixture / 'generated/client-a.json').read_text()).get('mcdata', {}).get('group_id', group)
        )
        data_server['mcdata']['location'] = dict(
            server['mcptt']['location'], group_areas={mcdata_group: dict(polygon=LOCATION_GROUP_AREA)}
        )
        data_file.write_text(json.dumps(data_server, indent=2) + '\n')
    # MCVideo (TS 24.281 clause 18): the same configuration and areas from the MCVideo
    # server, and the same rights in each MCVideo profile, naming MCVideo IDs.
    video_file = fixture / 'generated/mcvideo-server.json'
    if video_file.exists():
        video_server = json.loads(video_file.read_text())
        video_server['mcvideo']['location'] = copy.deepcopy(server['mcptt']['location'])
        video_file.write_text(json.dumps(video_server, indent=2) + '\n')
        site = json.loads(site_file.read_text())
        by_mcptt = {profile['mcptt_id']: profile for profile in site['users']}
        video_ids = {mcptt: by_mcptt[mcptt].get('mcvideo_id') for mcptt in rights}
        for mcptt, right in rights.items():
            if 'mcvideo' in by_mcptt[mcptt]:
                by_mcptt[mcptt]['mcvideo']['location'] = dict(
                    right,
                    **(
                        {
                            'share_with': [
                                video_ids.get(item, item) if item != '*' else item for item in right['share_with']
                            ]
                        }
                        if 'share_with' in right
                        else {}
                    ),
                )
        site_file.write_text(json.dumps(site, indent=2) + '\n')
    for item, role in enumerate(['client-a', 'client-b', 'client-c', 'client-d']):
        path = fixture / f'generated/{role}.json'
        cfg = json.loads(path.read_text())
        cfg['mcptt']['location'] = dict(position=[48.0, 2.0 + 0.01 * item])
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    add_seal_location(fixture)


# ------------------------------------------------------------------------------
def add_seal_location(fixture):
    """The SEAL location management server (TS 24.545) in the LMS: the clients
    report to it through the HTTP proxy, and the MCPTT and MCData servers use it
    as VAL servers with their server credentials."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    service = site['service_uri']
    site['seal_lm'] = dict(
        identity=f"sip:lms@{site['domain']}",
        periodic_seconds=2,
        minimum_interval=1,
        val_servers=[service, service.replace('sip:mcptt@', 'sip:mcdata@')],
    )
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    for path in sorted((fixture / 'generated').glob('*.json')):
        cfg = json.loads(path.read_text())
        if path.stem.startswith(('mcptt-server', 'mcptt-part', 'mcdata-server')) and 'common' in cfg:
            cfg['common']['lms'] = 'https://lms:8443'
        elif path.stem.startswith('client-') and 'endpoints' in cfg:
            cfg['endpoints']['lms'] = cfg['endpoints']['cms'].rsplit('/', 1)[0] + '/lms'
        else:
            continue
        path.write_text(json.dumps(cfg, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_msgstore(fixture):
    """Storage of communications in the MCData message store (TS 24.282 clause 21.3).

    client-a may store its private and group communications, client-b its private
    ones only, client-c none (<allow-store-comms-in-msgstore> absent), and client-d
    may store communications but not private ones."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    group = site['groups'][0]['id']
    rights = {
        'client-a': dict(store_comms=True, store_private_comms=True, store_group_comms=[group]),
        'client-b': dict(store_comms=True, store_private_comms=True),
        'client-d': dict(store_comms=True),
    }
    ids = {
        client: json.loads((fixture / f'generated/{client}.json').read_text())['mcdata']['user_id'] for client in rights
    }
    for user in site['users']:
        for role, right in rights.items():
            if user.get('mcdata_id') == ids[role]:
                user.setdefault('mcdata', {}).update(right)
    site_file.write_text(json.dumps(site, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_group_management(fixture):
    """Group document writes and subscriptions (TS 24.481 clauses 6.3.2 to 6.3.13): client-a may
    create groups and update user profiles (TS 24.484 clause 6.3.4), client-b manages the
    provisioned group, client-c and client-d manage nothing."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    group = site['groups'][0]['id']
    ids = {
        role: json.loads((fixture / f'generated/{role}.json').read_text())['mcptt']['user_id']
        for role in ['client-a', 'client-b']
    }
    for user in site['users']:
        if user['mcptt_id'] == ids['client-a']:
            user['group_management'] = dict(create=True)
            # An MC service administrator: updates others' profiles (TS 24.484 clause 6.3.4).
            user['config_management'] = True
        if user['mcptt_id'] == ids['client-b']:
            user['group_management'] = dict(manage=[group])
    site_file.write_text(json.dumps(site, indent=2) + '\n')


# ------------------------------------------------------------------------------
def service_configuration(fixture):
    """The site's service_config (TS 24.484 clauses 8.4, 9.4 and 10.4): the RFC 8101 Resource-Priority values of
    each service, and the MCPTT floor settings and MCData file availabilities the lab gave its servers. The clients
    and servers read them from the CMS, so no other file keeps Resource-Priority values."""
    generated = fixture / 'generated'
    resources = dict(emergency='mcpttp.15', imminent='mcpttp.10', normal='mcpttp.0')
    mcptt = dict(resource_priority=resources)
    mcdata = dict(resource_priority=resources)
    for path in sorted(generated.glob('*.json')):
        if path.name == 'site.json':
            continue
        cfg = json.loads(path.read_text())
        if not isinstance(cfg, dict):
            continue
        for service in ('mcptt', 'mcvideo', 'mcdata'):
            if isinstance(cfg.get(service), dict):
                cfg[service].pop('resource_priority', None)
        if path.name == 'mcptt-server.json':
            # <transmit-time>/<time-limit> (T2) and <floor-control-queue> of the MCPTT service configuration.
            if 'max_talk_ms' in cfg.get('mcptt', {}):
                mcptt['transmit_time_limit_ms'] = cfg['mcptt']['max_talk_ms']
            if cfg.get('mcptt', {}).get('floor_queue'):
                mcptt['floor_queue'] = True
        if path.name == 'mcdata-server.json':
            fd = cfg.get('mcdata', {}).get('fd', {})
            if 'default_file_availability_ms' in fd:
                mcdata['default_file_availability_s'] = max(1, fd['default_file_availability_ms'] // 1000)
            if 'max_file_availability_ms' in fd:
                mcdata['max_file_availability_s'] = max(1, fd['max_file_availability_ms'] // 1000)
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    site_file = generated / 'site.json'
    site = json.loads(site_file.read_text())
    for group in site['groups']:
        for policy in (group.get('priority_policy'), group.get('mcvideo', {}).get('priority_policy')):
            if isinstance(policy, dict):
                policy.pop('resource_priority', None)
    site['service_config'] = dict(mcptt=mcptt, mcvideo=dict(resource_priority=resources), mcdata=mcdata)
    site_file.write_text(json.dumps(site, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_broadcast_hierarchy(fixture, source):
    """Add a group-broadcast group over both prearranged groups (initiator a) and a
    user-broadcast group of b, c and d (TS 23.379 clause 10.6.2.5.2; project profile).
    client-c may start and cancel emergency calls on the second group, whose
    ongoing emergency call a group-broadcast must not preempt. client-a and
    client-b may raise and cancel emergency and imminent peril on the first
    group (emergency and imminent-peril broadcast)."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        client: json.loads((fixture / f'generated/{client}.json').read_text())['mcptt']['user_id']
        for client in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    first, second = site['groups'][0]['id'], site['groups'][1]['id']
    everyone = f"sip:{source['group_user']}-all@{source['domain']}"
    users = f"sip:{source['group_user']}-users@{source['domain']}"
    site['groups'] = [existing for existing in site['groups'] if existing['id'] not in (everyone, users)]
    site['groups'].append(
        dict(
            id=everyone,
            type='group-broadcast',
            members=[ids['client-a']],
            subordinate_groups=[first, second],
            protect_media=False,
            protect_floor=False,
        )
    )
    site['groups'].append(
        dict(
            id=users,
            type='user-broadcast',
            members=[ids['client-b'], ids['client-c'], ids['client-d']],
            protect_media=False,
            protect_floor=False,
        )
    )
    resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
    for group in site['groups']:
        if group['id'] == second:
            group.setdefault('priority_policy', {}).update(
                emergency_users=[ids['client-c']], emergency_cancel_users=[ids['client-c']], emergency_timeout_ms=300000
            )
        if group['id'] == first:
            # Emergency and imminent-peril broadcast (H7): client-a may raise and
            # cancel both; client-b is authorised too, so its refusal as a
            # broadcast receiver is not an authorisation failure.
            permitted = [ids['client-a'], ids['client-b']]
            group.setdefault('priority_policy', {}).update(
                emergency_users=permitted,
                emergency_cancel_users=permitted,
                imminent_users=permitted,
                imminent_cancel_users=permitted,
                emergency_timeout_ms=300000,
            )
    extra = {ids['client-a']: [everyone], ids['client-b']: [users], ids['client-c']: [users], ids['client-d']: [users]}
    for user in site['users']:
        user['groups'] += [existing for existing in extra.get(user['mcptt_id'], []) if existing not in user['groups']]
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    for role, added in [('client-a', [everyone]), ('client-b', [users]), ('client-c', []), ('client-d', [])]:
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        config['mcptt']['allowed_groups'] = config['mcptt'].get('allowed_groups', [first]) + added
        config['mcptt'].setdefault('resource_priority', resources)
        path.write_text(json.dumps(config, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_functional_aliases(fixture, source):
    """Functional aliases (TS 24.379 clause 9A) managed by the CMS: "dispatcher" for a
    and b (one activation, take-over allowed, b may take over) and "medic" for
    c and d (two activations); "reserve" has users but is never activated."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        role: json.loads((fixture / f'generated/{role}.json').read_text())['mcptt']['user_id']
        for role in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    alias = lambda name: f"sip:{name}.alias@{source['domain']}"
    site['functional_aliases'] = [
        dict(
            id=alias('dispatcher'),
            users=[ids['client-a'], ids['client-b']],
            max_simultaneous_activations=1,
            allow_takeover=True,
        ),
        dict(id=alias('medic'), users=[ids['client-c'], ids['client-d']], max_simultaneous_activations=2),
        dict(id=alias('reserve'), users=[ids['client-a']], max_simultaneous_activations=1),
    ]
    for user in site['users']:
        if user['mcptt_id'] == ids['client-b']:
            user['functional_alias_takeover'] = True
        # Both medic users must be reachable by private calls in this fixture.
        if user['mcptt_id'] == ids['client-d'] and 'private_call' in user:
            user['private_call']['callable'] = True
    site_file.write_text(json.dumps(site, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_private_services(fixture):
    """Private call services (TS 24.379 clauses 11.1.5 to 11.1.9) on top of --private-call:
    client-a may request call-backs, remotely initiated calls and transfers and
    forward manually; client-b may forward manually; client-c forwards every
    private call immediately to client-b, and may also call client-d (an announced
    transfer target); client-d becomes callable and forwards
    to client-a on no answer after 3 s (TS 24.379 clause 6.3.2.5). A fifth user,
    "offline", never registers and forwards to client-a on no answer, so it is
    forwarded at once (TS 24.379 clause 11.1.1.3.2 step 6). Each user may be in two private calls at a time, as a
    transferred user is while it calls the target."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        role: json.loads((fixture / f'generated/{role}.json').read_text())['mcptt']['user_id']
        for role in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    for user in site['users']:
        policy = user.setdefault('private_call', {})
        if user['mcptt_id'] == ids['client-a']:
            policy.update(callback=True, callback_cancel=True, remote_init=True, transfer=True, forward_manual=True)
            # client-a calls client-d to announce a transfer (TS 24.379 clause 11.1.8.2.3).
            policy['targets'] = sorted(set(policy.get('targets', [])) | {ids['client-d']})
        elif user['mcptt_id'] == ids['client-b']:
            policy.update(forward_manual=True)
        elif user['mcptt_id'] == ids['client-c']:
            policy.update(forward_immediate=ids['client-b'])
        elif user['mcptt_id'] == ids['client-d']:
            policy.update(callable=True, forward_no_answer=ids['client-a'], forward_no_answer_timeout_ms=3000)
    template = next(profile for profile in site['users'] if profile['mcptt_id'] == ids['client-d'])
    offline = {
        key: value.replace('client-d', 'offline') if isinstance(value, str) else value
        for key, value in template.items()
    }
    offline.update(
        client_id=f'urn:uuid:{uuid.uuid4()}',
        groups=[],
        private_call=dict(callable=True, forward_no_answer=ids['client-a']),
    )
    offline.pop('mcdata', None)
    offline.pop('mcdata_id', None)
    site['users'] = [profile for profile in site['users'] if profile['username'] != 'offline'] + [offline]
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    # TS 24.379 clause 11.1.8.2.2: the transferred user keeps its call with the requester while it calls the target,
    # so it is briefly in two private calls; the limit (N10, TS 24.484 <MaxCall>) must allow that.
    server_file = fixture / 'generated/mcptt-server.json'
    server = json.loads(server_file.read_text())
    server['mcptt']['private_call']['max_calls'] = 2
    server_file.write_text(json.dumps(server, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_mcvideo_policy(fixture):
    """MCVideo configuration for the MCVideo server scenario (TS 24.281 clauses 7.2.2, 8.2).

    Each client gets an "mcvideo" section: its MCVideo ID, the MCVideo PSI and the
    group operations, of which all four users are MCVideo members. The extra group
    video-closed has client-a as its only member, MCPTT and MCVideo alike, so an
    affiliation of anyone else to it is refused. Chat group video-chat has all
    four users as MCPTT and MCVideo members (TS 24.281 clause 9.2.2). The MCVideo server queues
    Transmission Requests, revokes a transmission after 15 s and applies reception
    control (TS 24.581 clause 4.1.1.2); client-d does not queue, so its request while another
    user transmits is rejected, and it accepts each transmission by hand.
    MCVideo private-call rulesets (TS 24.281 clause 10.2, in each user's "mcvideo" profile):
    client-a all commencement modes to client-b and client-c; client-b automatic and
    manual to anyone; client-c automatic only to anyone, called only by client-a;
    client-d may neither call nor be called.
    Priority (TS 24.281 clauses 4.6, 6.2.8): on operations, client-a and client-b may raise and
    cancel emergency and imminent peril group calls and emergency alerts (only client-a
    cancels alerts); client-a may make emergency private calls to anyone.
    """
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    service = json.loads((fixture / 'generated/mcvideo-server.json').read_text())['mcvideo']['service_uri']
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    configs = {client: json.loads((fixture / f'generated/{client}.json').read_text()) for client in roles}
    by_mcptt = {profile['mcptt_id']: profile for profile in site['users']}
    video_ids = {client: by_mcptt[configs[client]['mcptt']['user_id']]['mcvideo_id'] for client in roles}
    group = site['groups'][0]
    resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
    permitted = [video_ids['client-a'], video_ids['client-b']]
    group['mcvideo'] = dict(
        members=[video_ids[client] for client in roles],
        priority_policy=dict(
            emergency_users=permitted,
            emergency_cancel_users=permitted,
            imminent_users=permitted,
            imminent_cancel_users=permitted,
            alert_users=permitted,
            alert_cancel_users=[video_ids['client-a']],
            resource_priority=resources,
            emergency_timeout_ms=300000,
        ),
    )
    private = {
        'client-a': dict(
            allow=True,
            automatic_commencement=True,
            manual_commencement=True,
            force_auto_answer=True,
            targets=[video_ids['client-b'], video_ids['client-c']],
            emergency=True,
            emergency_any=True,
            emergency_cancel=True,
            # V7: <allow-request-remote-initiated-ambient-viewing> and
            # <allow-request-locally-initiated-ambient-viewing> (TS 24.484).
            ambient_remote=True,
            ambient_local=True,
        ),
        'client-b': dict(allow=True, automatic_commencement=True, manual_commencement=True, any_target=True),
        'client-c': dict(
            allow=True, automatic_commencement=True, any_target=True, incoming_from=[video_ids['client-a']]
        ),
        'client-d': dict(allow=False, callable=False),
    }
    # V6 (TS 24.281 clauses 12.2, 13.2; TS 24.581 clauses 9.2.22 to 9.2.25), project profile names where
    # TS 24.484 has no element (tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md): client-a may
    # start and end other users' transmissions remotely (<allow-revoke-transmit> for
    # the end) and push to and pull from the server; client-b may pull from the server;
    # client-c and client-d may do none of these.
    video_rights = {
        'client-a': dict(
            allow_remote_transmit=True,
            allow_revoke_transmit=True,
            allow_video_push_to_server=True,
            allow_video_pull_from_server=True,
        ),
        'client-b': dict(allow_video_pull_from_server=True),
        'client-c': {},
        'client-d': {},
    }
    # V8a (TS 24.281 clause 22): ad hoc group calls as in the MCPTT profile
    # (<allow-adhoc-group-call>, <allow-to-modify-adhoc-group-call-participants-info>):
    # everyone but client-d; only client-a may modify the participants.
    for role in roles:
        video_rights[role]['adhoc_call'] = dict(allow=role != 'client-d')
    video_rights['client-a']['adhoc_call'].update(modify=True)
    # TS 24.281 clause 12.1A: client-a may also raise and cancel an ad hoc group emergency alert
    # (<allow-activate-adhoc-group-emergency-alert>, <allow-cancel-adhoc-group-emergency-alert>).
    video_rights['client-a']['adhoc_call'].update(alert=True, alert_cancel=True)
    for role in roles:
        by_mcptt[configs[role]['mcptt']['user_id']]['mcvideo'] = dict(private_call=private[role], **video_rights[role])
    domain = group['id'].split('@', 1)[1]
    closed = copy.deepcopy(group)
    closed['id'] = f'sip:video-closed@{domain}'
    closed['members'] = [configs['client-a']['mcptt']['user_id']]
    closed['mcvideo'] = dict(members=[video_ids['client-a']])
    site['groups'].append(closed)
    chat = copy.deepcopy(group)
    chat.update(id=f'sip:video-chat@{domain}', type='chat')
    site['groups'].append(chat)
    # V8b (TS 24.281 clause 21): a preconfigured group that only gives a regroup its
    # configuration (<preconfigured-group-use-only>); client-a may regroup
    # (<allow-regroup>), client-b may not.
    preconf = copy.deepcopy(group)
    preconf.update(id=f'sip:video-regroup@{domain}', preconfigured_use_only=True)
    # The regroup takes its whole configuration from it (TS 24.281 clause 21.1), priority policy included.
    preconf['mcvideo'] = dict(
        copy.deepcopy(group['mcvideo']), members=[video_ids[client] for client in roles], preconfigured_use_only=True
    )
    site['groups'].append(preconf)
    # V8d (TS 24.281 clause 9.2.4): a second prearranged group, video-field, of which all four
    # are MCVideo members but none is affiliated at the start; client-a may change the
    # selected group of client-b and client-d (<RemoteGroupSelectionURIList>).
    field = copy.deepcopy(group)
    field['id'] = f'sip:video-field@{domain}'
    site['groups'].append(field)
    by_mcptt[configs['client-a']['mcptt']['user_id']]['mcvideo']['remote_group_selection'] = [
        video_ids['client-b'],
        video_ids['client-d'],
    ]
    for user in site['users']:
        if 'mcvideo' in user:
            user['mcvideo']['regroup'] = user['mcptt_id'] == configs['client-a']['mcptt']['user_id']
    # V8c (TS 24.281 clause 20; <mcvideo-user-list> of TS 24.484 clause 9.4.2): video-dispatcher
    # for client-a and client-b, one activation, take-over allowed, and only client-b
    # has <allow-takeover-functional-alias-other-user>; video-medic for client-b and
    # client-c, two activations.
    # Only client-b has <allow-functional-alias-binding-with-group> (TS 24.281 clause 20.4.2.2.2 step 4a).
    alias = lambda name: f'sip:{name}.alias@{domain}'
    site['functional_aliases'] = [
        entry
        for entry in site.get('functional_aliases', [])
        if entry['id'] not in (alias('video-dispatcher'), alias('video-medic'))
    ]
    site['functional_aliases'] += [
        dict(
            id=alias('video-dispatcher'),
            users=[],
            mcvideo_users=[video_ids['client-a'], video_ids['client-b']],
            max_simultaneous_activations=1,
            allow_takeover=True,
        ),
        dict(
            id=alias('video-medic'),
            users=[],
            mcvideo_users=[video_ids['client-b'], video_ids['client-c']],
            max_simultaneous_activations=2,
        ),
    ]
    by_mcptt[configs['client-b']['mcptt']['user_id']]['mcvideo'].update(
        functional_alias_takeover=True, functional_alias_binding=True
    )
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    server_file = fixture / 'generated/mcvideo-server.json'
    server = json.loads(server_file.read_text())
    server['mcvideo']['adhoc_call'] = dict(
        enabled=True,
        max_participants=3,
        setup_timeout_ms=5000,
        inactivity_timeout_ms=60000,
        maximum_duration_ms=60000,
        end_when_initiator_leaves=True,
    )
    server['mcvideo'].update(
        floor_queue=True,
        max_talk_ms=15000,
        reception_control=True,
        private_call=dict(setup_timeout_ms=5000, max_calls=1),
        resource_priority=resources,
    )
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    for role in roles:
        # The MCVideo call's own ports, apart from the MCPTT call's media.rtp_port and floor_port.
        configs[role]['mcvideo'] = dict(
            user_id=video_ids[role],
            service_uri=service,
            group_id=group['id'],
            media=dict(audio_port=4200, control_port=5200, video_port=6200),
            queueing=role != 'client-d',
            auto_receive=role != 'client-d',
            resource_priority=resources,
        )
        # Synthetic TS 23.032 encoded fields for the isolated simulator only.
        configs[role]['mcptt'].setdefault('emergency_location', dict(latitude=1, longitude=2))
        (fixture / f'generated/{role}.json').write_text(json.dumps(configs[role], indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_group_subscription(fixture):
    """The MCData server subscribes, as an MCS server, to the group documents it reads
    (TS 24.481 clause 6.3.13.2.2) at the PSI of the GMS's subscription proxy function, which
    the MCPTT servers provide and which accept the MCData server's PSI."""
    data_path = fixture / 'generated/mcdata-server.json'
    data = json.loads(data_path.read_text())
    for path in sorted((fixture / 'generated').glob('mcptt-*.json')):
        cfg = json.loads(path.read_text())
        cfg['mcptt']['mcs_servers'] = [data['mcdata']['service_uri']]
        if path.name == 'mcptt-server.json':
            data['mcdata']['group_subscription_uri'] = cfg['mcptt']['service_uri']
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    data_path.write_text(json.dumps(data, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_mcdata_policy(fixture, source):
    """MCData rulesets and groups for the SDS scenario (TS 24.282 clauses 9.2.2, 11.1); the
    numbers in brackets are the TS 24.282 warning codes a scenario expects.

    client-a: may send, one-to-one targets b and c only, at most 300 bytes per request
    client-b: may send, receives one-to-one SDS only from client-a
    client-c: may send, no one-to-one limits, not allowed to send on the group
    client-d: not allowed to transmit data
    Ad hoc group SDS: a and b may initiate, c may not (238), d may not take part
    (241); at most 3 participants (242).
    Emergency alert (TS 24.282 clause 16.2): a may alert on any group allowing alerts and cancel;
    b may alert only on its dedicated group operations-nosds; c may neither alert
    nor cancel; d may cancel alerts of others. Groups operations and
    operations-nosds allow alerts; operations-alertonly excludes a (120);
    operations-preconf is preconfigured-use-only (168 for alerts, 167 for SDS);
    operations-regrouped is marked regrouped (148).
    Implicit affiliation (TS 24.282 clause 8.3.2.15): client-d to operations-alertonly.
    Functional aliases (TS 24.282 clause 22): desk.fa (a, b; one activation; take-over allowed and
    b holds the take-over permission), medic.fa (c, d; two activations) and
    reserve.fa (a; never activated).
    Service limits: 1000 bytes over the signalling plane, 500 bytes per one-to-one SDS.
    Group operations: all four members, at most 400 bytes per SDS and 800 per request.
    Extra groups: operations-nosds (SDS and FD not allowed), operations-nosupport
    (no SDS or FD enabler) and operations-noemergency (SDS allowed, but neither
    emergency nor imminent peril group communications).
    Priority group communications (TS 24.282 clause 6.2.8.1): client-a may initiate and cancel both
    an emergency and an imminent peril group communication, client-b only an
    imminent peril one, and client-c neither (233, 236).
    File distribution over HTTP (TS 24.282 clause 10.2.4): client-b may release another user's file
    distribution (TS 24.282 clause 13.2.5); TDC3 is 6 s and an extension adds 120 s.
    Group operations allows FD with at most
    2000 bytes per file; the service allows 4000; files of at most 64 bytes are
    auto-received; TDC2 is 20 s by default (the sender can ask for less) and TDU2 8 s.
    """
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = {
        client: json.loads((fixture / f'generated/{client}.json').read_text())['mcdata']['user_id']
        for client in ['client-a', 'client-b', 'client-c', 'client-d']
    }
    policies = {
        ids['client-a']: dict(
            transmit_data=True,
            targets=[ids['client-b'], ids['client-c']],
            max_data_1to1=300,
            incoming_any=True,
            adhoc=True,
            adhoc_participation=True,
            emergency_alert=True,
            alert_cancel=True,
            organization='Alpha Fire',
            emergency_private=True,
            emergency_private_cancel=True,
            emergency_group=True,
            emergency_group_cancel=True,
            imminent_peril=True,
            imminent_peril_cancel=True,
        ),
        ids['client-b']: dict(
            transmit_data=True,
            incoming_from=[ids['client-a']],
            adhoc=True,
            adhoc_participation=True,
            functional_alias_takeover=True,
            emergency_alert=True,
            release_any_user=True,
            imminent_peril=True,
            imminent_peril_cancel=True,
            alert_groups=[f"sip:{source['group_user']}-nosds@{source['domain']}"],
        ),
        ids['client-c']: dict(transmit_data=True, incoming_any=True, adhoc_participation=True),
        ids['client-d']: dict(
            transmit_data=False,
            incoming_any=True,
            alert_cancel=True,
            alert_cancel_any_user=True,
            implicit_affiliations=[f"sip:{source['group_user']}-alertonly@{source['domain']}"],
        ),
    }
    for user in site['users']:
        if user.get('mcdata_id') in policies:
            user['mcdata'] = policies[user['mcdata_id']]
    everyone = list(ids.values())
    first = site['groups'][0]['id']
    for group in site['groups']:
        if group['id'] == first:
            group['mcdata'] = dict(
                members=everyone,
                sds_supported=True,
                allow_sds=True,
                transmit_members=[ids['client-a'], ids['client-b'], ids['client-d']],
                max_sds_bytes=400,
                max_request_bytes=800,
                allow_emergency_alert=True,
                allow_emergency_call=True,
                allow_imminent_peril=True,
                allow_fd=True,
                fd_supported=True,
                max_fd_bytes=2000,
                # Enhanced status (TS 24.282 clause 14.2): three operational values.
                allow_enhanced_status=True,
                enhanced_status_values=[
                    dict(id='1', value='On scene'),
                    dict(id='2', value='En route'),
                    dict(id='3', value='Available'),
                ],
            )
    for suffix, settings, extra in [
        (
            'nosds',
            dict(sds_supported=True, allow_sds=False, allow_emergency_alert=True, fd_supported=True, allow_fd=False),
            {},
        ),
        ('nosupport', dict(sds_supported=False, allow_sds=True, allow_fd=True, fd_supported=False), {}),
        (
            'alertonly',
            dict(
                sds_supported=True,
                allow_sds=True,
                allow_emergency_alert=True,
                members=[ids['client-b'], ids['client-c'], ids['client-d']],
            ),
            {},
        ),
        (
            'preconf',
            dict(sds_supported=True, allow_sds=True, allow_emergency_alert=True),
            dict(preconfigured_use_only=True),
        ),
        ('regrouped', dict(sds_supported=True, allow_sds=True), dict(regrouped=True)),
        # Neither priority group communication is allowed on this group (233, 236).
        # Operational values without <mcdata-allow-enhanced-status> (TS 24.282 clause 14.2.1.1).
        (
            'noemergency',
            dict(sds_supported=True, allow_sds=True, enhanced_status_values=[dict(id='1', value='On scene')]),
            {},
        ),
    ]:
        gid = f"sip:{source['group_user']}-{suffix}@{source['domain']}"
        site['groups'] = [existing for existing in site['groups'] if existing['id'] != gid]
        site['groups'].append(
            dict(
                id=gid,
                members=[profile['mcptt_id'] for profile in site['users']],
                protect_media=False,
                protect_floor=False,
                mcdata=dict(dict(members=everyone), **settings),
                **extra,
            )
        )
    aliases = {
        f"sip:{name}.fa@{source['domain']}": dict(users, max_simultaneous_activations=limit, allow_takeover=takeover)
        for name, users, limit, takeover in [
            ('desk', dict(mcdata_users=[ids['client-a'], ids['client-b']]), 1, True),
            ('medic', dict(mcdata_users=[ids['client-c'], ids['client-d']]), 2, False),
            ('reserve', dict(mcdata_users=[ids['client-a']]), 1, False),
        ]
    }
    site['functional_aliases'] = [entry for entry in site.get('functional_aliases', []) if entry['id'] not in aliases]
    site['functional_aliases'] += [dict(id=alias, users=[], **settings) for alias, settings in aliases.items()]
    site['mcdata_service'] = dict(site.get('mcdata_service', {}), max_data_size_fd_bytes=4000)
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    server_file = fixture / 'generated/mcdata-server.json'
    server = json.loads(server_file.read_text())
    server['mcdata'].update(max_payload_size_sds_cplane_bytes=1000, max_data_size_sds_bytes=500)
    server['mcdata']['adhoc'] = dict(allow=True, max_participants=3, lifetime_ms=1800000)
    server['mcdata']['redelivery'] = dict(tdp1_ms=2000, max_attempts=2, retention_ms=600000, max_held=1000)
    server['mcdata']['aggregation'] = dict(enabled=True, tdc1_ms=3000, max_per_message=50)
    # File distribution over HTTP: small files are auto-received (TS 24.282 clause 11.2), and the file
    # availability timer TDC2 is short enough to observe its expiry.
    # The media plane session is released by the server if it outlives its purpose.
    # An SDS session is released after this long without traffic.
    server['mcdata']['media'] = dict(session_ms=20000, idle_ms=25000)
    server['mcdata']['fd'] = dict(
        server['mcdata'].get('fd', {}),
        max_data_size_auto_recv_bytes=64,
        max_file_availability_ms=600000,
        default_file_availability_ms=20000,
        tdc3_ms=6000,
        extension_ms=120000,
    )
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    for role in ids:
        path = fixture / f'generated/{role}.json'
        cfg = json.loads(path.read_text())
        # TDU1 long enough for a scripted display indication; application ID 7 is known.
        # A file offered over the media plane without a mandatory download is
        # auto-received up to this size, and declined above it (TS 24.282 clause 11.2 with
        # clause 10.2.5.2.4).
        cfg['mcdata'].update(
            tdu1_ms=3000, tdu2_ms=8000, applications=[7], fd=dict(cfg['mcdata'].get('fd', {}), auto_receive_bytes=300)
        )
        path.write_text(json.dumps(cfg, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_mcdata_release_policy(fixture):
    """Communication release (TS 24.282 clause 13) over the media plane: a
    communication is released by the server after 20 s or 5000 bytes, without prior
    indication; TDC3 is 5 s, and the server accepts an extension request. The media
    idle timer (25 s) is longer than the time limit, so the limit is what ends an
    idle session."""
    server_file = fixture / 'generated/mcdata-server.json'
    server = json.loads(server_file.read_text())
    server['mcdata']['release'] = dict(
        max_duration_ms=20000,
        max_bytes=5000,
        prior_indication=False,
        tdc3_ms=5000,
        accept_extension=True,
        initiator_leave=True,
    )
    server_file.write_text(json.dumps(server, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_chat_group(fixture, source):
    """Add a chat group (TS 24.379 clause 10.1.2) that every fixture user may select."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    chat = f"sip:{source['group_user']}-chat@{source['domain']}"
    members = [profile['mcptt_id'] for profile in site['users']]
    site['groups'] = [existing for existing in site['groups'] if existing['id'] != chat]
    # Group call_policy replaces the server default for this group only.
    # Emergency and imminent peril chat calls (TS 24.379 clause 10.1.2.4.1 steps 14 to 15)
    # are authorised for clients a-c; client-d is not.
    resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
    permitted = members[:3]
    priority = dict(
        emergency_users=permitted,
        emergency_cancel_users=permitted,
        imminent_users=permitted,
        imminent_cancel_users=permitted,
        resource_priority=resources,
        emergency_timeout_ms=300000,
    )
    # client-c has a higher <user-priority> and displaces a participant at the
    # limit (TS 24.379 clause 10.1.2.4.1 step 12a); two further chat groups carry the
    # <preconfigured-group-use-only> and regrouped restrictions (steps 4b to 4c).
    site['groups'].append(
        dict(
            id=chat,
            type='chat',
            members=members,
            protect_media=False,
            protect_floor=False,
            call_policy=dict(max_participants=3, inactivity_timeout_ms=20000),
            priority_policy=priority,
            user_priorities={members[2]: 10},
        )
    )
    restricted = [
        f"sip:{source['group_user']}-chat-{kind}@{source['domain']}" for kind in ('preconfigured', 'regrouped')
    ]
    site['groups'] = [existing for existing in site['groups'] if existing['id'] not in restricted]
    site['groups'].append(
        dict(
            id=restricted[0],
            type='chat',
            members=members,
            protect_media=False,
            protect_floor=False,
            preconfigured_use_only=True,
        )
    )
    site['groups'].append(
        dict(id=restricted[1], type='chat', members=members, protect_media=False, protect_floor=False, regrouped=True)
    )
    for user in site['users']:
        for group in [chat] + restricted:
            if group not in user['groups']:
                user['groups'].append(group)
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    first = site['groups'][0]['id']
    for role in ['client-a', 'client-b', 'client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        allowed = config['mcptt'].get('allowed_groups', [first])
        config['mcptt']['allowed_groups'] = allowed + [chat] + restricted
        config['mcptt'].setdefault('resource_priority', resources)
        path.write_text(json.dumps(config, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_regroup_policy(fixture, source):
    """A preconfigured group and two constituent groups for a regroup (TS 24.379 clause 16).

    The regroup takes its configuration from the preconfigured group, which is
    marked <preconfigured-group-use-only> so that it cannot be called directly,
    and its members are the union of the two constituent groups. client-a may
    create and remove regroups; client-b may not, so 160 and 161 can be seen."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    ids = [profile['mcptt_id'] for profile in site['users']]
    domain, group_user = source['domain'], source['group_user']
    preconf = f'sip:{group_user}-preconf@{domain}'
    north, south = f'sip:{group_user}-north@{domain}', f'sip:{group_user}-south@{domain}'
    policy = dict(
        end_when_initiator_leaves=False, setup_timeout_ms=5000, minimum_participants=2, inactivity_timeout_ms=60000
    )
    # A second preconfigured group of type chat, so that a regroup over the same
    # constituents carries a chat group call (TS 24.379 clause 10.1.2.4.1 steps 5, 5a and 11b).
    chat_preconf = f'sip:{group_user}-chat-preconf@{domain}'
    keep = {preconf, chat_preconf, north, south}
    site['groups'] = [existing for existing in site['groups'] if existing['id'] not in keep]
    site['groups'].append(
        dict(
            id=preconf,
            members=ids,
            protect_media=False,
            protect_floor=False,
            preconfigured_use_only=True,
            call_policy=policy,
        )
    )
    site['groups'].append(
        dict(
            id=chat_preconf,
            type='chat',
            members=ids,
            protect_media=False,
            protect_floor=False,
            preconfigured_use_only=True,
            call_policy=dict(policy, max_participants=4, inactivity_timeout_ms=60000),
        )
    )
    site['groups'].append(dict(id=north, members=ids[:2], protect_media=False, protect_floor=False, call_policy=policy))
    site['groups'].append(dict(id=south, members=ids[2:], protect_media=False, protect_floor=False, call_policy=policy))
    for index, user in enumerate(site['users']):
        user['regroup'] = index == 0
        if index == 0:
            user.setdefault('group_management', {})['temporary'] = True
        for group in [north] if index < 2 else [south]:
            if group not in user['groups']:
                user['groups'].append(group)
        for group in (preconf, chat_preconf):
            if group not in user['groups']:
                user['groups'].append(group)
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    for index, role in enumerate(['client-a', 'client-b', 'client-c', 'client-d']):
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        own = north if index < 2 else south
        config['mcptt']['group_id'] = own
        config['mcptt']['allowed_groups'] = sorted(
            {own, north, south, preconf, chat_preconf} | set(config['mcptt'].get('allowed_groups', []))
        )
        path.write_text(json.dumps(config, indent=2) + '\n')


# ------------------------------------------------------------------------------
def add_adhoc_policy(fixture):
    """Enable ad hoc group calls (TS 24.379 clause 17) with client-d unauthorised.
    Only client-a may start emergency or imminent peril ad hoc calls or modify
    participants; TNG2 is 12 s so its release is observable."""
    site_file = fixture / 'generated/site.json'
    site = json.loads(site_file.read_text())
    denied = json.loads((fixture / 'generated/client-d.json').read_text())['mcptt']['user_id']
    priority_user = json.loads((fixture / 'generated/client-a.json').read_text())['mcptt']['user_id']
    for user in site['users']:
        user['adhoc_call'] = dict(allow=user['mcptt_id'] != denied)
        if user['mcptt_id'] == priority_user:
            # <allow-to-modify-adhoc-group-call-participants-info> too (TS 24.379 clause 17.4.5.1.1 step 3).
            # ... and <allow-activate/cancel-adhoc-group-emergency-alert> (TS 24.379 clause 12.1A).
            user['adhoc_call'].update(emergency=True, imminent=True, modify=True, alert=True, alert_cancel=True)
    site_file.write_text(json.dumps(site, indent=2) + '\n')
    server_file = fixture / 'generated/mcptt-server.json'
    server = json.loads(server_file.read_text())
    server['mcptt']['adhoc_call'] = dict(
        enabled=True,
        max_participants=3,
        setup_timeout_ms=5000,
        inactivity_timeout_ms=60000,
        maximum_duration_ms=30000,
        end_when_initiator_leaves=True,
        emergency_timeout_ms=12000,
    )
    resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
    server['mcptt'].setdefault('resource_priority', resources)
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    for role in ['client-a', 'client-b', 'client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        config['mcptt'].setdefault('resource_priority', resources)
        path.write_text(json.dumps(config, indent=2) + '\n')


# ------------------------------------------------------------------------------
def status_probes(gen, site, args):
    """The services the MCX Admin dashboard checks: health URLs, or the SIP ports."""
    https = lambda name, url: dict(name=name, url=url)
    # With --debug-sip the servers listen on sip.debug_port (default 5060) over TCP.
    sip = lambda role: json.loads((gen / f'{role}.json').read_text())['sip']
    sip_port = lambda role: sip(role).get('debug_port', 5060) if args.debug_sip else sip(role)['port']
    return [
        https('IdMS', site['endpoints']['idms'] + '/readyz'),
        https('Configuration management (CMS)', 'https://cms:8443/readyz'),
        https('Group management (GMS)', 'https://gms:8443/readyz'),
        https('Key management (KMS)', 'https://kms:8443/readyz'),
        https('Credential Service', 'https://credentials:8443/readyz'),
        https('HTTP proxy', 'https://http-proxy:8443/readyz'),
        dict(name='SIP core', tcp=f'sip-core:{5060 if args.debug_sip else 5061}'),
        dict(name='MCPTT server', tcp=f'mcptt-server:{sip_port("mcptt-server")}'),
        dict(name='MCData server', tcp=f'mcdata-server:{sip_port("mcdata-server")}'),
    ]


# ------------------------------------------------------------------------------
def add_pcf(fixture):
    """N5 (TS 29.514): the MCPTT server's "pcf" block, pointing at mock-pcf. The lab network's addresses are assigned by
    Docker, so every client address counts as a 5G UE. Without --pcf the server has no "pcf" block: N5 off."""
    path = fixture / 'generated/mcptt-server.json'
    cfg = json.loads(path.read_text())
    cfg['pcf'] = dict(enabled=True, pcf_uri='http://mock-pcf:8080', dnn='mcptt', snssai=dict(sst=1),
                      af_app_id='mcptt', notif_bind='0.0.0.0:8099', notif_uri_base='http://mcptt-server:8099/npcf-af',
                      ue_subnets=['0.0.0.0/0'], audio_bw_kbps=41, required=False,
                      prio_map=dict(normal='', imminent='PRIO_12', emergency='PRIO_16'))
    path.write_text(json.dumps(cfg, indent=2) + '\n')


def add_mock_pcf(compose, fixture):
    """The mock PCF: tests/integration/mock_pcf.go, run with the Go toolchain of the development image."""
    server = compose['services']['mcptt-server']
    compose['services']['mock-pcf'] = {
        'image': 'openmcx-dev:0.1',
        'init': True,
        'entrypoint': ['go', 'run', '/mock/mock_pcf.go'],
        'command': ['-listen', ':8080', '-record', '/artifacts/mock-pcf/requests.jsonl'],
        'environment': {'GOCACHE': '/tmp/go-cache', 'GOPATH': '/tmp/go', 'HOME': '/tmp'},
        'working_dir': '/tmp',
        'volumes': [{'type': 'bind', 'source': str(ROOT / 'tests/integration/mock_pcf.go'), 'target': '/mock/mock_pcf.go',
                     'read_only': True},
                    {'type': 'bind', 'source': str(fixture / 'artifacts'), 'target': '/artifacts'}],
        'networks': copy.deepcopy(server['networks']),
        'healthcheck': {'test': ['CMD', 'curl', '-sf', '--http2-prior-knowledge', 'http://127.0.0.1:8080/healthz'],
                        'interval': '2s', 'timeout': '3s', 'retries': 60, 'start_period': '5s'},
    }
    server.setdefault('depends_on', {})['mock-pcf'] = {'condition': 'service_healthy'}


# The Rx lab's network: Docker assigns addresses from the lower half (the EPS UEs of rx.ue_subnets); client-d has a
# fixed address in the upper half, a UE on an access without dedicated bearers (WLAN, TS 24.379 clause 4.13).
RX_LAB_SUBNET, RX_LAB_EPS, RX_LAB_WLAN_CLIENT = '10.231.0.0/24', '10.231.0.0/25', '10.231.0.200'


def add_rx(fixture):
    """Rx (TS 29.214, MCPTT-5): the MCPTT server's "rx" block and the mock PCRF as a Diameter peer of its core, which
    MCPTT-2 shares: over SCTP like MCPTT-2 but without TLS (the mock has none). client-a to client-c are EPS UEs,
    client-d is on WLAN. Without --rx the server has no "rx" block: Rx off."""
    path = fixture / 'generated/mcptt-server.json'
    cfg = json.loads(path.read_text())
    domain = json.loads((fixture / 'generated/site.json').read_text())['domain']
    cfg['rx'] = dict(enabled=True, destination_realm=domain, destination_host=f'mock-pcrf.{domain}',
                     ue_subnets=[RX_LAB_EPS], audio_bw_kbps=41, required=False)
    path.write_text(json.dumps(cfg, indent=2) + '\n')
    conf = fixture / 'generated/diameter-server.conf'
    peer = f'ConnectTo = "mock-pcrf"; TcTimer = 5; Port = 3868; No_TCP; No_TLS; Realm = "{domain}";'
    comment = '# Rx to the mock PCRF (TS 29.214), over SCTP without TLS.'
    conf.write_text(conf.read_text() + f'{comment}\nConnectPeer = "mock-pcrf.{domain}" {{ {peer} }};\n')


def add_mock_pcrf(compose, fixture):
    """The mock PCRF (tests/integration/mock_pcrf.py, with the Python of the development image) and the Rx lab's
    network: a fixed subnet, client-d outside rx.ue_subnets."""
    domain = json.loads((fixture / 'generated/site.json').read_text())['domain']
    server = compose['services']['mcptt-server']
    compose['services']['mock-pcrf'] = {
        'image': 'openmcx-dev:0.1',
        'init': True,
        'entrypoint': ['python3', '/mock/mock_pcrf.py'],
        'command': ['--identity', f'mock-pcrf.{domain}', '--realm', domain, '--record',
                    '/artifacts/mock-pcrf/requests.jsonl'],
        'volumes': [{'type': 'bind', 'source': str(ROOT / 'tests/integration/mock_pcrf.py'),
                     'target': '/mock/mock_pcrf.py', 'read_only': True},
                    {'type': 'bind', 'source': str(fixture / 'artifacts'), 'target': '/artifacts'}],
        'networks': copy.deepcopy(server['networks']),
        'healthcheck': {'test': ['CMD', 'curl', '-sf', 'http://127.0.0.1:8080/healthz'],
                        'interval': '2s', 'timeout': '3s', 'retries': 60, 'start_period': '2s'},
    }
    (fixture / 'artifacts/mock-pcrf').mkdir(parents=True, exist_ok=True)
    server.setdefault('depends_on', {})['mock-pcrf'] = {'condition': 'service_healthy'}
    compose['networks']['mcx']['ipam'] = {'config': [{'subnet': RX_LAB_SUBNET, 'ip_range': RX_LAB_EPS}]}
    compose['services']['client-d']['networks'] = {'mcx': {'ipv4_address': RX_LAB_WLAN_CLIENT}}


def rights_from_group_lists(fixture):
    """TS 24.379 clause 6.3.3.1.13 and TS 24.281 clause 6.3.3.1.12: an emergency group call, imminent peril call or emergency alert needs
    the right in the caller's user profile (TS 24.484) and the group document's action for the caller (TS 24.481);
    cancelling an alert or imminent peril needs the profile right. The labs name who may in the groups' priority
    policies (the action for each listed member); every user a list names gets the matching profile right, so a lab
    authorises exactly whom its lists name. An MCData group without transmit_members lets every member transmit
    (transmit_all, <mcdata-allow-transmit-data-in-this-group> for all members), as the labs expect."""
    site_file = fixture / 'generated/site.json'
    if not site_file.exists():
        return
    site = json.loads(site_file.read_text())
    rights = dict(emergency_users='emergency', imminent_users='imminent', imminent_cancel_users='imminent_cancel',
                  alert_users='alert', alert_cancel_users='alert_cancel', emergency_cancel_users='emergency_cancel')
    by_mcptt = {user['mcptt_id']: user for user in site['users']}
    by_mcvideo = {user.get('mcvideo_id'): user for user in site['users'] if user.get('mcvideo_id')}
    for group in site['groups']:
        for key, right in rights.items():
            for member in group.get('priority_policy', {}).get(key, []):
                if member in by_mcptt:
                    by_mcptt[member].setdefault('group_call', {})[right] = True
            for member in group.get('mcvideo', {}).get('priority_policy', {}).get(key, []):
                if member in by_mcvideo:
                    video = by_mcvideo[member].setdefault('mcvideo', {})
                    video.setdefault('group_call', {})[right] = True
        if 'mcdata' in group and 'transmit_members' not in group['mcdata']:
            group['mcdata']['transmit_all'] = True
    # <allow-adhoc-group-call-participation> (TS 24.379 clause 17.4.2.2.1 step 6): every user the labs may invite to
    # an ad hoc group call, unless a lab says otherwise.
    for user in site['users']:
        for policy in (user.get('adhoc_call'), user.get('mcvideo', {}).get('adhoc_call')):
            if isinstance(policy, dict):
                policy.setdefault('participation', True)
        user.setdefault('adhoc_call', {'allow': False, 'participation': True}).setdefault('participation', True)
    site_file.write_text(json.dumps(site, indent=2) + '\n')


def add_admin(fixture, compose, args):
    """MCX Admin manages the accounts.

    mcxadmin seeds its store from this site.json, in its own database on the lab's
    MySQL; IdMS and the CMS take accounts and user records from it; mcx-user-db
    follows the users file it writes. IdMS starts with verifiers of the lab users'
    passwords, so that the clients sign in as before; alice (client-a) is an
    administrator (config_management).

    Slice F1: the Credential Service (mcx-common role credentials) holds the SIP
    credentials of accounts it issues, in the SIP core's subscriber table, and moves
    them aside on suspension; mcxadmin issues activation URLs. client-e, in the
    profile "activation", is a client with local settings only: admin_scenario.py
    creates its user and starts it with an activation URL."""
    import base64
    import hashlib
    import secrets as admin_secrets

    gen = fixture / 'generated'
    site_path = gen / 'site.json'
    site = json.loads(site_path.read_text())
    site['users'][0]['config_management'] = True
    site['admin_accounts'] = dict(url='https://mcxadmin:8443', link_base_url=site['endpoints']['idms'])
    # Slice F2: the Credential Service certifies devices' keys with the system CA, whose
    # key only its container mounts.
    rpc_url = 'http://sip-core:5060/RPC' if args.debug_sip else 'https://sip-core:5061/RPC'
    site['credentials'] = dict(
        mysql_dsn_file='/config/credentials-dsn',
        issuer_cert_file='/config/tls/ca.crt',
        issuer_key_file='/config/issuer/ca.key',
        certificate_days=30,
        # The revocation list the SIP core reads, reloaded over its operator RPC.
        crl_file='/crl/devices.crl',
        sip_core_rpc=rpc_url,
        client_cert_file='/config/tls/credentials.crt',
        client_key_file='/config/tls/credentials.key',
        ca_file='/config/tls/ca.crt',
    )
    # Slice E1: the console signs administrators in at IdMS with the lab's OAuth client.
    console_callback = 'https://mcxadmin:8443/ui/callback'
    site['oauth_redirect_uris'] = [*site['oauth_redirect_uris'], console_callback]
    site_path.write_text(json.dumps(site, indent=2) + '\n')
    password, credentials_password = admin_secrets.token_hex(24), admin_secrets.token_hex(24)
    (gen / 'mcxadmin.sql').write_text(
        "CREATE DATABASE IF NOT EXISTS mcxadmin;\n"
        f"CREATE USER 'mcxadmin'@'%' IDENTIFIED BY '{password}';\n"
        "GRANT ALL ON mcxadmin.* TO 'mcxadmin'@'%';\n"
        "CREATE TABLE mcx.subscriber_suspended LIKE mcx.subscriber;\n"
        f"CREATE USER 'credentials'@'%' IDENTIFIED BY '{credentials_password}';\n"
        "GRANT SELECT, INSERT, UPDATE, DELETE ON mcx.subscriber TO 'credentials'@'%';\n"
        "GRANT SELECT, INSERT, UPDATE, DELETE ON mcx.subscriber_suspended TO 'credentials'@'%';\n"
        "CREATE TABLE mcx.client_certificates (serial VARCHAR(64) PRIMARY KEY, username VARCHAR(64) NOT NULL, "
        "domain VARCHAR(64) NOT NULL, client_id VARCHAR(255) NOT NULL, not_after DATETIME NOT NULL, "
        "issued_at DATETIME NOT NULL, revoked_at DATETIME NULL, KEY (username, domain));\n"
        "GRANT SELECT, INSERT, UPDATE ON mcx.client_certificates TO 'credentials'@'%';\n"
    )
    (gen / 'mcxadmin.sql').chmod(0o644)  # read by the MySQL image's own user, as sip-db.sql
    (gen / 'credentials-dsn').write_text(f'credentials:{credentials_password}@tcp(sip-db:3306)/mcx\n')
    (gen / 'mcxadmin-dsn').write_text(f'mcxadmin:{password}@tcp(sip-db:3306)/mcxadmin?parseTime=true\n')
    (gen / 'server-secret').write_text(site['server_secret'] + '\n')
    client = json.loads((gen / 'client-a.json').read_text())
    activation = dict(
        base_url='https://mcxadmin:8443',
        ttl_seconds=3600,
        idms={field: client['oauth'][field] for field in ('issuer', 'client_id', 'redirect_uri')},
        sip_core_uri=client['sip']['core_uri'],
        credentials_url='https://credentials:8443',
        services=dict(mcptt=client['mcptt']['service_uri'], mcdata=client.get('mcdata', {}).get('service_uri', '')),
        endpoints=client['endpoints'],
        trust_root_file='/config/tls/ca.crt',
    )
    (gen / 'mcxadmin.json').write_text(
        json.dumps(
            dict(
                listen=':8443',
                domain=site['domain'],
                tls_cert='/config/tls/mcxadmin.crt',
                tls_key='/config/tls/mcxadmin.key',
                mysql_dsn_file='/config/mcxadmin-dsn',
                projections=dict(
                    userdb_file='/shared/userdb.json',
                    credentials_url='https://credentials:8443',
                    gms_url='https://gms:8443',
                ),
                idms=dict(
                    url=site['endpoints']['idms'],
                    client_id=site['server_client_id'],
                    secret_file='/config/server-secret',
                    ca_file='/config/tls/ca.crt',
                ),
                activation=activation,
                console=dict(
                    authorize_url=site['endpoints']['idms'] + '/authorize',
                    client_id=site['oauth_client_id'],
                    redirect_uri=console_callback,
                ),
                status=dict(services=status_probes(gen, site, args), sip_core_rpc=rpc_url),
            ),
            indent=2,
        )
        + '\n'
    )
    # client-e: the local settings of a device (its ports, paths and TLS files), no
    # identity; activation fills in the rest and marks the file, which is writable.
    device = json.loads((gen / 'client-c.json').read_text().replace('client-c', 'client-e'))
    for key in ('oauth', 'mcdata', 'msgstore', 'endpoints'):
        device.pop(key, None)
    for key in ('core_uri', 'identity', 'username', 'password'):
        device['sip'].pop(key, None)
    device['mcptt'] = {
        field: item
        for field, item in device['mcptt'].items()
        if field not in ('user_id', 'client_id', 'service_uri', 'group_id')
    }
    # No device certificate: activation makes a key and the Credential Service certifies
    # it (slice F2); only the system CA is local.
    device['tls'] = {'ca_file': device['tls']['ca_file']}
    activate = gen / 'activate-e'
    activate.mkdir()
    (activate / 'client-e.json').write_text(json.dumps(device, indent=2) + '\n')
    # The SIP core refuses SDP whose address is not the sender's (TS 24.229 clause 5.2.7.2),
    # so the MCPTT server accepts the address of a user its configuration names no
    # device for, such as erin, whom admin_scenario.py creates at runtime.
    server_file = gen / 'mcptt-server.json'
    server = json.loads(server_file.read_text())
    server['sip']['core_checks_media_address'] = True
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    # A copy of the local settings, for activating the device again (ADM-09).
    (activate / 'device.json').write_text(json.dumps(device, indent=2) + '\n')
    for name in ('client-e.json', 'device.json'):
        (activate / name).chmod(0o666)
    activate.chmod(0o777)

    # IdMS's credential file: PBKDF2-HMAC-SHA256 verifiers in its own format
    # (services/internal/common/idms_accounts.go), of the passwords the clients use.
    # ------------------------------------------------------------------------------
    def verifier(secret):
        """An IdMS verifier of secret: PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt."""
        salt = admin_secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt, 600000, 32)
        b64 = lambda raw: base64.b64encode(raw).decode().rstrip('=')
        return f'$pbkdf2-sha256$600000${b64(salt)}${b64(key)}'

    data = gen / 'idms-data'
    data.mkdir()
    (data / 'idms-credentials.json').write_text(
        json.dumps(dict(verifiers={user['username']: verifier(user['password']) for user in site['users']}, links={}))
        + '\n'
    )
    data.chmod(0o777)
    (data / 'idms-credentials.json').chmod(0o666)
    services = compose['services']
    # The SIP core checks clients' SDP addresses (route[CLIENT_SDP_ADDRESS]), which the
    # MCPTT server's core_checks_media_address relies on for users created in MCX Admin.
    core = services['sip-core']
    command = core.get('command') or ['-DD', '-E', '-f', '/config/kamailio.cfg']
    at = command.index('-f')
    # CORE_RPC: MCX Admin reads the registrations for its dashboard, and the Credential
    # Service reloads TLS after a new revocation list (event_route[xhttp:request]).
    core['command'] = command[:at] + ['-A', 'CLIENT_SDP_CHECK', '-A', 'CORE_RPC'] + command[at:]
    bind = lambda source, target, read_only=True: dict(
        type='bind', source=str(source), target=target, read_only=read_only
    )
    shared = dict(type='volume', source='userdb', target='/shared')
    compose['volumes']['userdb'] = dict(name=args.project + '_userdb')
    services['sip-db']['volumes'].append(bind(gen / 'mcxadmin.sql', '/docker-entrypoint-initdb.d/02-mcxadmin.sql'))
    services['mcxadmin'] = dict(
        image=args.admin_image,
        command=['--config', '/config/mcxadmin.json', '--seed', '/config/site.json'],
        volumes=[
            bind(gen / 'site.json', '/config/site.json'),
            bind(gen / 'mcxadmin.json', '/config/mcxadmin.json'),
            bind(gen / 'mcxadmin-dsn', '/config/mcxadmin-dsn'),
            bind(gen / 'server-secret', '/config/server-secret'),
            bind(gen / 'tls/ca.crt', '/config/tls/ca.crt'),
            bind(gen / 'tls/mcxadmin.crt', '/config/tls/mcxadmin.crt'),
            bind(gen / 'tls/mcxadmin.key', '/config/tls/mcxadmin.key'),
            shared,
        ],
        networks=copy.deepcopy(services['cms']['networks']),
        depends_on={'sip-db': {'condition': 'service_healthy'}},
        healthcheck=dict(
            test=[
                'CMD',
                'curl',
                '--fail',
                '--silent',
                '--cacert',
                '/config/tls/ca.crt',
                'https://mcxadmin:8443/healthz',
            ],
            interval='2s',
            timeout='3s',
            retries=60,
        ),
    )
    credentials = json.loads(
        json.dumps(copy.deepcopy(services['cms']))
        .replace('/cms.', '/credentials.')
        .replace('https://cms:', 'https://credentials:')
    )
    credentials['command'][credentials['command'].index('--role') + 1] = 'credentials'
    credentials['volumes'] = [item for item in credentials['volumes'] if item.get('target') != '/data'] + [
        bind(gen / 'credentials-dsn', '/config/credentials-dsn'),
        bind(gen / 'issuer', '/config/issuer'),
    ]
    # The revocation list: an empty one signed by the CA to start with (the SIP core reads it
    # at start), then the Credential Service's; shared, written by that service only.
    crl = gen / 'crl'
    crl.mkdir(exist_ok=True)
    (crl / 'index.txt').write_text('')
    (crl / 'crlnumber').write_text('01\n')
    (crl / 'openssl.cnf').write_text(
        f"[ca]\ndefault_ca = lab\n[lab]\ndatabase = {crl / 'index.txt'}\ncrlnumber = {crl / 'crlnumber'}\n"
        "default_md = sha256\ndefault_crl_days = 30\n"
    )
    subprocess.run(
        [
            'openssl',
            'ca',
            '-gencrl',
            '-config',
            str(crl / 'openssl.cnf'),
            '-keyfile',
            str(gen / 'tls/ca.key'),
            '-cert',
            str(gen / 'tls/ca.crt'),
            '-out',
            str(crl / 'devices.crl'),
        ],
        check=True,
        capture_output=True,
    )
    for filename in ('index.txt', 'crlnumber', 'openssl.cnf', 'index.txt.attr', 'crlnumber.old'):
        (crl / filename).unlink(missing_ok=True)
    (crl / 'devices.crl').chmod(0o666)
    crl.chmod(0o777)
    credentials['volumes'].append(bind(crl, '/crl', read_only=False))
    services['sip-core']['volumes'].append(bind(crl, '/crl'))
    if not args.debug_sip:
        # The SIP core refuses a revoked device certificate at the TLS handshake.
        tls_cfg = gen / 'tls.cfg'
        tls_cfg.write_text(
            tls_cfg.read_text().replace('[server:default]\n', '[server:default]\ncrl = /crl/devices.crl\n', 1)
        )
    issuer = gen / 'issuer'
    issuer.mkdir(exist_ok=True)
    shutil.copyfile(gen / 'tls/ca.key', issuer / 'ca.key')
    (issuer / 'ca.key').chmod(0o644)  # read by the service's own user in its container; the lab's CA key
    issuer.chmod(0o755)
    credentials['tmpfs'] = [*credentials.get('tmpfs', []), '/data']
    credentials['depends_on'] = {'sip-db': {'condition': 'service_healthy'}}
    services['credentials'] = credentials
    services['mcxadmin']['depends_on']['credentials'] = {'condition': 'service_healthy'}
    services['mcxadmin']['depends_on']['gms'] = {'condition': 'service_healthy'}
    # The services that read users from MCX Admin in admin mode reach it over TLS.
    for name in ('idms', 'cms', 'credentials', 'gms', 'kms', 'lms'):
        if '--ca-file' not in services[name]['command']:
            services[name]['command'] += ['--ca-file', '/config/tls/ca.crt']
    # client-e starts only when admin_scenario.py has written its activation URL.
    client_e = json.loads(json.dumps(copy.deepcopy(services['client-c'])).replace('client-c', 'client-e'))
    client_e['volumes'] = [
        item
        for item in client_e['volumes']
        if item.get('target') not in ('/config/client-e.json', '/config/tls/client-e.crt', '/config/tls/client-e.key')
    ] + [bind(activate, '/config/activate', read_only=False)]
    client_e['entrypoint'] = [
        'sh',
        '-c',
        'exec /usr/local/bin/mcx-client "$@" --activate "$(cat /config/activate/url)" '
        '--password-file /config/activate/password',
        'mcx-client',
    ]
    client_e['command'] = [
        ('/config/activate/client-e.json' if argument == '/config/client-e.json' else argument)
        for argument in client_e['command']
    ]
    client_e['profiles'] = ['activation']
    client_e['depends_on'] = {'mcxadmin': {'condition': 'service_healthy'}}
    services['client-e'] = client_e
    services['idms']['volumes'] = [item for item in services['idms']['volumes'] if item.get('target') != '/data'] + [
        bind(data, '/data', read_only=False)
    ]
    userdb = services['mcx-user-db']
    userdb['command'] = [
        '--config',
        '/shared/userdb.json',
        '--diameter-config',
        '/config/diameter-user-db.conf',
        '--watch',
    ]
    userdb['volumes'].append(dict(shared, read_only=True))
    userdb.setdefault('depends_on', {})['mcxadmin'] = {'condition': 'service_healthy'}


# ------------------------------------------------------------------------------
def main():
    """Parse the command line, provision the lab, apply the flags and write compose.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'artifacts/prearranged-lab')
    parser.add_argument('--input', type=Path, default=ROOT / 'config/lab.json')
    parser.add_argument('--project', default='openmcx-prearranged')
    parser.add_argument('--debug-sip', action='store_true')
    parser.add_argument('--floor-queue', action='store_true')
    parser.add_argument('--priority', action='store_true')
    parser.add_argument('--protected', action='store_true')
    parser.add_argument(
        '--xml-protection',
        action='store_true',
        help='With --protected: MCPTT XML confidentiality protection (TS 24.379 6.6.2)',
    )
    parser.add_argument(
        '--integrity-protection',
        action='store_true',
        help='With --protected: MCPTT XML integrity protection (TS 24.379 6.6.3)',
    )
    parser.add_argument(
        '--private-call',
        action='store_true',
        help='Provision differentiated private-call profile policies; with --protected, '
        'private calls carry an end-to-end PCK (TS 33.180 7.2)',
    )
    parser.add_argument(
        '--private-refresh',
        action='store_true',
        help='With --private-call, use a 70 s private call timer so a call outlasts the SIP refresh point',
    )
    parser.add_argument(
        '--broadcast', action='store_true', help='Restrict broadcast group call initiation to client-a and client-b'
    )
    parser.add_argument(
        '--regroup',
        action='store_true',
        help='Add a preconfigured group and two constituent groups for regroup (TS 24.379 clause 16)',
    )
    parser.add_argument(
        '--chat', action='store_true', help='Add a four-member chat group (max 3 participants, 20 s inactivity)'
    )
    parser.add_argument(
        '--adhoc',
        action='store_true',
        help='Enable ad hoc group calls (max 3 invitees, 5 s setup, 30 s call timer); client-d not authorised',
    )
    parser.add_argument(
        '--private-services',
        action='store_true',
        help='With --private-call, add call-back, remote-call, transfer and forwarding permissions',
    )
    parser.add_argument('--mcdata', action='store_true', help='Provision differentiated MCData rulesets and SDS groups')
    parser.add_argument(
        '--mcvideo',
        action='store_true',
        help='Add mcvideo-server: openmcx-mcvideo-server with the MCVideo service profile (TS 24.281), and '
        "give every client its MCVideo ID, the MCVideo PSI and the MCVideo group and private-call policy",
    )
    parser.add_argument(
        '--sign-payloads',
        action='store_true',
        help='With --mcdata --protected, sign every DATA PAYLOAD (TS 33.180 8.5.5)',
    )
    parser.add_argument(
        '--mcdata-release', action='store_true', help='With --mcdata, add the communication release limits of clause 13'
    )
    parser.add_argument(
        '--functional-alias',
        action='store_true',
        help='Provision functional aliases dispatcher, medic and reserve (TS 24.379 9A)',
    )
    parser.add_argument(
        '--group-management',
        action='store_true',
        help='Group document writes and subscriptions (TS 24.481 6.3.2-6.3.13)',
    )
    parser.add_argument(
        '--msgstore',
        action='store_true',
        help='Storage of MCData communications in the message store (TS 24.282 21.3); needs --mcdata',
    )
    parser.add_argument(
        '--location', action='store_true', help='Location reporting, requests and areas (TS 24.379 clause 13, 6.3.2.4)'
    )
    parser.add_argument(
        '--split',
        action='store_true',
        help='Separate participating and controlling servers (H2): mcptt-server controls every call; '
        'mcptt-part-1 serves client-a and client-c, mcptt-part-2 client-b and client-d; with --mcvideo '
        'likewise mcvideo-server, mcvideo-part-1 and mcvideo-part-2',
    )
    parser.add_argument(
        '--pcf',
        action='store_true',
        help='N5 AF role (TS 29.514): mcptt-server requests QoS from mock-pcf, a recording mock PCF '
        '(tests/integration/mock_pcf.go) over HTTP/2 cleartext; every client counts as a 5G UE',
    )
    parser.add_argument(
        '--rx',
        action='store_true',
        help='Rx AF role (TS 29.214): mcptt-server requests QoS from mock-pcrf, a recording mock PCRF '
        '(tests/integration/mock_pcrf.py) over Diameter; client-a to client-c are EPS UEs, client-d is on WLAN',
    )
    parser.add_argument(
        '--admin',
        action='store_true',
        help='MCX Admin manages the accounts (admin mode of IdMS, CMS and user database; needs --admin-image)',
    )
    parser.add_argument('--admin-image', help='the MCX Admin image (built from the openmcx-admin repository)')
    parser.add_argument(
        '--token-ttl',
        type=int,
        help='IdMS access token lifetime in seconds instead of the input\'s (token renewal tests)',
    )
    parser.add_argument('--image', help='Application image for MCx services instead of the compose default')
    parser.add_argument(
        '--images',
        metavar='TAG',
        help='per-program images openmcx-<program>:TAG (docker/Dockerfile targets) instead of one application image',
    )
    parser.add_argument(
        '--client-image', help='mcx-client image (built from the openmcx-client repository) instead of the compose default'
    )
    parser.add_argument(
        '--key-parameters-iei',
        type=lambda spec: int(spec, 0),
        help='Explicit interoperability-profile IEI; not assigned by supplied TS33.180',
    )
    args = parser.parse_args()
    if (args.xml_protection or args.integrity_protection) and not args.protected:
        parser.error("--xml-protection and --integrity-protection require --protected")
    if args.protected and (args.key_parameters_iei is None or not 0 <= args.key_parameters_iei <= 255):
        parser.error('--protected requires an explicit --key-parameters-iei interoperability value')
    if args.project == 'openmcx':
        parser.error('choose a project different from the original openmcx lab')
    if args.private_refresh and not args.private_call:
        parser.error('--private-refresh requires --private-call')
    fixture = args.directory.resolve()
    if fixture.exists():
        parser.error(f'refusing to overwrite existing fixture {fixture}')
    source = json.loads(args.input.read_text())
    if args.token_ttl is not None:
        if args.token_ttl < 60:
            parser.error('--token-ttl must be at least 60 seconds')
        source['token_ttl_seconds'] = args.token_ttl
    if args.admin and not args.admin_image:
        parser.error('--admin needs --admin-image')
    if args.admin:
        source['extra_roles'] = [*source.get('extra_roles', []), 'mcxadmin', 'credentials', 'client-e']
    if [user['role'] for user in source['users']] != ['client-a', 'client-b']:
        parser.error('input must contain client-a and client-b, in that order')
    for role in ['client-c', 'client-d']:
        # Fixture identities derive from the new role and configured domain.
        source['users'].append(dict(role=role, username=role, mcptt_user=role + '.mcptt'))
    if args.split:
        source['servers'] = [
            dict(name='mcptt-server', role='controlling'),
            dict(name='mcptt-part-1', role='participating', users=['client-a', 'client-c']),
            dict(name='mcptt-part-2', role='participating', users=['client-b', 'client-d']),
        ]
        if args.mcvideo:
            # TS 24.281 clauses 6.3.2, 6.3.3: MCVideo split the same way, with the controlling
            # function on mcvideo-server.
            source['mcvideo_servers'] = [
                dict(name='mcvideo-server', role='controlling'),
                dict(name='mcvideo-part-1', role='participating', users=['client-a', 'client-c']),
                dict(name='mcvideo-part-2', role='participating', users=['client-b', 'client-d']),
            ]
    servers = [spec['name'] for spec in source.get('servers', [dict(name='mcptt-server')])]
    video_servers = (
        [spec['name'] for spec in source.get('mcvideo_servers', [dict(name='mcvideo-server')])] if args.mcvideo else []
    )
    if (
        len({user['username'] for user in source['users']}) != 4
        or len({user['mcptt_user'] for user in source['users']}) != 4
    ):
        parser.error('fixture identities conflict with input users')
    os.umask(0o077)
    fixture.mkdir(parents=True)
    (fixture / 'tools').mkdir()
    (fixture / 'docker').mkdir()
    # Provisioner derives its artifacts root from __file__; copy it to isolate
    # even its mkdir operations from the original lab's artifacts.
    shutil.copyfile(ROOT / 'tools/provision.py', fixture / 'tools/provision.py')
    shutil.copyfile(ROOT / 'docker/kamailio.cfg', fixture / 'docker/kamailio.cfg')
    (fixture / 'lab.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(
        [
            'python3',
            str(fixture / 'tools/provision.py'),
            '--input',
            str(fixture / 'lab.json'),
            '--output',
            str(fixture / 'generated'),
        ],
        check=True,
    )
    add_parallel_group(fixture, source)
    server_file = fixture / 'generated/mcptt-server.json'
    server = json.loads(server_file.read_text())
    server['mcptt']['call_policy'] = dict(end_when_initiator_leaves=True, setup_timeout_ms=3000, minimum_participants=2)
    server_file.write_text(json.dumps(server, indent=2) + '\n')
    for role in servers + ['client-a', 'client-b', 'client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        cfg = json.loads(path.read_text())
        cfg['sip']['session_expires'] = 90
        cfg['mcptt']['floor_queue'] = args.floor_queue
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    if args.priority or args.protected:
        site_path = fixture / 'generated/site.json'
        site = json.loads(site_path.read_text())
        users = {
            client: json.loads((fixture / f'generated/{client}.json').read_text())['mcptt']['user_id']
            for client in ['client-a', 'client-b', 'client-c', 'client-d']
        }
        resources = dict(normal='mcpttp.0', imminent='mcpttp.10', emergency='mcpttp.15')
        wire_profile = dict(
            message_type=10, algorithm=1, key_parameters_iei=args.key_parameters_iei, encrypted_payload_iei=0x78
        )
        if args.protected:
            site['security'] = dict(key_parameter_profile=wire_profile)
        for group in site['groups']:
            if args.protected:
                group['protect_media'] = group['protect_floor'] = True
            if args.priority:
                permitted = [users['client-a'], users['client-b']]
                group['priority_policy'] = dict(
                    emergency_users=permitted,
                    emergency_cancel_users=permitted,
                    imminent_users=permitted,
                    imminent_cancel_users=permitted,
                    alert_users=permitted,
                    alert_cancel_users=[users['client-a']],
                    resource_priority=resources,
                    emergency_timeout_ms=300000,
                    floor_preemptive_users=[users['client-b']],
                    preemptive_priority=75,
                    num_levels=99,
                )
                group['floor_priority_caps'] = {id: (90 if role == 'client-b' else 10) for role, id in users.items()}
        site_path.write_text(json.dumps(site, indent=2) + '\n')
        for role in servers + ['client-a', 'client-b', 'client-c', 'client-d']:
            path = fixture / f'generated/{role}.json'
            cfg = json.loads(path.read_text())
            if args.priority:
                cfg['mcptt']['resource_priority'] = resources
                cfg['mcptt']['maximum_floor_priority'] = 90 if role == 'client-b' else 10
                cfg['mcptt']['floor_priority'] = 10
                if role not in servers:
                    # Synthetic TS 23.032 encoded fields for the isolated simulator only.
                    cfg['mcptt']['emergency_location'] = dict(latitude=1, longitude=2)
            if args.protected:
                cfg['security'] = dict(
                    kms_uri=site['endpoints']['kms'],
                    gms_uri=site['endpoints']['gms'] + '/xcap-root/org.openmobilealliance.groups',
                    key_parameter_profile=wire_profile,
                    protect_media=True,
                    protect_floor=True,
                    confidentiality_protection=args.xml_protection,
                    integrity_protection=args.integrity_protection,
                )
                if role in servers:
                    cfg['common']['kms'] = site['endpoints']['kms']
            path.write_text(json.dumps(cfg, indent=2) + '\n')
        if args.protected and args.mcvideo:
            # TS 24.281 clauses 4.7 and 6.6: the MCVideo server keys its own identity, holds its
            # users' CSKs, and protects MCVideo signalling as the MCPTT server does.
            for name in video_servers:
                path = fixture / f'generated/{name}.json'
                cfg = json.loads(path.read_text())
                cfg['security'] = dict(
                    kms_uri=site['endpoints']['kms'],
                    gms_uri=site['endpoints']['gms'] + '/xcap-root/org.openmobilealliance.groups',
                    key_parameter_profile=wire_profile,
                    protect_media=True,
                    protect_floor=True,
                    confidentiality_protection=args.xml_protection,
                    integrity_protection=args.integrity_protection,
                )
                cfg['common']['kms'] = site['endpoints']['kms']
                path.write_text(json.dumps(cfg, indent=2) + '\n')
    # TS 33.180 clause 5.5: an SPK (purpose tag 3), its SPK-ID and SPK-RAND, provisioned into
    # both servers of each pair of one service; it protects the floor and transmission
    # control between them (TS 33.180 clause 9.4.5).
    for group_servers, section in ((servers, 'mcptt'), (video_servers, 'mcvideo')):
        if not args.protected or len(group_servers) < 2:
            continue
        import secrets as spk_random

        keys = {}
        for first in group_servers:
            for second in group_servers:
                if first < second:
                    keys[(first, second)] = dict(
                        id=0x30000000 | spk_random.randbits(28),
                        key=spk_random.token_hex(16),
                        rand=spk_random.token_hex(16),
                    )
        for name in group_servers:
            path = fixture / f'generated/{name}.json'
            cfg = json.loads(path.read_text())
            for other, entry in cfg[section].get('servers', {}).items():
                entry['spk'] = keys[tuple(sorted((name, other)))]
            path.write_text(json.dumps(cfg, indent=2) + '\n')
    if args.private_call:
        add_private_call_policy(fixture, args.private_refresh)
    if args.chat:
        add_chat_group(fixture, source)
    if args.adhoc:
        add_adhoc_policy(fixture)
    if args.regroup:
        add_regroup_policy(fixture, source)
    if args.functional_alias:
        add_functional_aliases(fixture, source)
    if args.mcvideo:
        add_mcvideo_policy(fixture)
    if args.mcdata:
        add_mcdata_policy(fixture, source)
        add_group_subscription(fixture)
        if args.protected:
            # TS 33.180 clause 8: end-to-end protected MCData payloads (PCK one-to-one, GMK
            # group); TS 33.180 clause 9.5: signalling protected with each client's CSK; clause 9.3:
            # sensitive XML content encrypted with it.
            client_security = json.loads((fixture / 'generated/client-a.json').read_text())['security']
            for role in ['client-a', 'client-b', 'client-c', 'client-d', 'mcdata-server']:
                path = fixture / f'generated/{role}.json'
                cfg = json.loads(path.read_text())
                cfg['mcdata']['protect_signalling'] = True
                cfg['mcdata']['confidentiality_protection'] = True  # TS 24.282 clause 6.5.2 (XML)
                if role == 'mcdata-server':
                    cfg['security'] = dict(
                        kms_uri=client_security['kms_uri'],
                        key_parameter_profile=client_security['key_parameter_profile'],
                    )
                else:
                    cfg['mcdata']['protect_payload'] = True
                    cfg['mcdata']['authenticate_payload'] = args.sign_payloads
                path.write_text(json.dumps(cfg, indent=2) + '\n')
    if args.mcdata_release:
        if not args.mcdata:
            parser.error('--mcdata-release requires --mcdata')
        add_mcdata_release_policy(fixture)
    if args.private_services:
        if not args.private_call:
            parser.error('--private-services requires --private-call')
        add_private_services(fixture)
    if args.broadcast:
        server_file = fixture / 'generated/mcptt-server.json'
        server = json.loads(server_file.read_text())
        initiators = [
            json.loads((fixture / f'generated/{client}.json').read_text())['mcptt']['user_id']
            for client in ['client-a', 'client-b']
        ]
        server['mcptt']['call_policy']['broadcast_members'] = initiators
        # Broadcast override (TS 23.379 clause 10.6.2.5 NOTE 3): client-d may take over.
        server['mcptt']['call_policy']['broadcast_overriders'] = [
            json.loads((fixture / 'generated/client-d.json').read_text())['mcptt']['user_id']
        ]
        server_file.write_text(json.dumps(server, indent=2) + '\n')
        add_broadcast_hierarchy(fixture, source)
    if args.group_management:
        add_group_management(fixture)
    if args.msgstore:
        if not args.mcdata:
            parser.error('--msgstore requires --mcdata')
        add_msgstore(fixture)
    if args.location:
        if args.split:
            parser.error('--location runs on a combined server')
        add_location(fixture)
    if args.pcf:
        if args.split:
            parser.error('--pcf runs on a combined server')
        add_pcf(fixture)
    if args.rx:
        if args.split:
            parser.error('--rx runs on a combined server')
        add_rx(fixture)
    # Scenario clients leave authorisation to the server so its rejections are
    # exercised; the private-services lab keeps client-d enforcing its profile.
    for role in ['client-a', 'client-b', 'client-c', 'client-d']:
        path = fixture / f'generated/{role}.json'
        config = json.loads(path.read_text())
        config['mcptt']['enforce_profile_ruleset'] = args.private_services and role == 'client-d'
        path.write_text(json.dumps(config, indent=2) + '\n')
    # The MCVideo service settings above were written to mcvideo-server; the
    # participating MCVideo servers take the same, keeping their own role and peers.
    if len(video_servers) > 1:
        controlling = json.loads((fixture / 'generated/mcvideo-server.json').read_text())
        own = ('role', 'servers', 'controller')
        for name in video_servers[1:]:
            path = fixture / f'generated/{name}.json'
            cfg = json.loads(path.read_text())
            cfg['mcvideo'] = {
                **{field: value for field, value in controlling['mcvideo'].items() if field not in own},
                **{field: value for field, value in cfg['mcvideo'].items() if field in own},
            }
            for key in ('security',):
                if key in controlling:
                    cfg[key] = controlling[key]
            if 'kms' in controlling['common']:
                cfg['common']['kms'] = controlling['common']['kms']
            path.write_text(json.dumps(cfg, indent=2) + '\n')
    compose_bin = ROOT / '.cache/deps/docker-compose-linux-x86_64'
    profiles = ['--profile', 'mcvideo'] if args.mcvideo else []
    rendered = subprocess.run(
        [str(compose_bin), '-f', str(ROOT / 'compose.yaml'), *profiles, 'config', '--format', 'json'],
        check=True,
        capture_output=True,
        text=True,
    )
    compose = json.loads(rendered.stdout)
    compose['name'] = args.project
    for service in compose['services'].values():
        service.pop('profiles', None)  # selected above; the lab starts every service it lists
    for kind in ['networks', 'volumes']:
        for key, definition in compose[kind].items():
            definition['name'] = args.project + '_' + key
    for role in ['client-c', 'client-d']:
        # Replace role strings in both mount source/target and health commands.
        compose['services'][role] = json.loads(
            json.dumps(copy.deepcopy(compose['services']['client-a'])).replace('client-a', role)
        )
    for name in servers:
        if name == 'mcptt-server':
            continue
        # A further MCPTT server: its own configuration, certificate, Diameter
        # identity and status file; the same executable.
        service = json.loads(
            json.dumps(copy.deepcopy(compose['services']['mcptt-server'])).replace('mcptt-server', name)
        )
        service['entrypoint'] = compose['services']['mcptt-server']['entrypoint']
        for mount in service['volumes']:
            if mount['target'] == '/config/diameter-server.conf':
                mount['source'] = mount['source'].replace('diameter-server.conf', f'diameter-{name}.conf')
        compose['services'][name] = service
    for name in video_servers[1:]:
        # A further MCVideo server, as for MCPTT.
        compose['services'][name] = json.loads(
            json.dumps(copy.deepcopy(compose['services']['mcvideo-server'])).replace('mcvideo-server', name)
        )
        compose['services'][name]['entrypoint'] = compose['services']['mcvideo-server']['entrypoint']
    for role in ['client-a', 'client-b', 'client-c', 'client-d']:
        for name in servers + video_servers[1:]:
            compose['services'][role]['depends_on'][name] = {'condition': 'service_healthy'}
    for service in compose['services'].values():
        for mount in service.get('volumes', []):
            if mount['type'] != 'bind':
                continue
            old = Path(mount['source'])
            if old.is_relative_to(ROOT / 'config/generated'):
                mount['source'] = str(fixture / 'generated' / old.relative_to(ROOT / 'config/generated'))
            elif old == ROOT / 'artifacts':
                mount['source'] = str(fixture / 'artifacts')
            else:
                raise RuntimeError(f'unexpected bind source {old}')
    client_default = compose['services']['client-a']['image']
    if args.images:
        lab_images.use_program_images(compose['services'], compose['services']['mcptt-server']['image'], args.images)
    elif args.image:
        default = compose['services']['mcptt-server']['image']
        for service in compose['services'].values():
            if service.get('image') == default:
                service['image'] = args.image
    if args.client_image:
        for service in compose['services'].values():
            if service.get('image') == client_default:
                service['image'] = args.client_image
    if args.protected:
        for name in servers:
            compose['services'][name].setdefault('depends_on', {})['kms'] = {'condition': 'service_healthy'}
        if args.mcdata:
            compose['services']['mcdata-server'].setdefault('depends_on', {})['kms'] = {'condition': 'service_healthy'}
        for name in video_servers:
            compose['services'][name].setdefault('depends_on', {})['kms'] = {'condition': 'service_healthy'}
        compose['services']['gms']['depends_on'] = {'kms': {'condition': 'service_healthy'}}
    if args.debug_sip:
        core = compose['services']['sip-core']
        core['command'] = ['-DD', '-E', '-A', 'SIP_DEBUG_NO_TLS', '-f', '/config/kamailio.cfg']
        core['healthcheck']['test'] = ['CMD-SHELL', 'nc -z 127.0.0.1 5060']
        for role in servers + ['mcdata-server', 'client-a', 'client-b', 'client-c', 'client-d'] + video_servers:
            compose['services'][role]['command'].append('--disable-tls')
    if args.pcf:
        add_mock_pcf(compose, fixture)
    if args.rx:
        add_mock_pcrf(compose, fixture)
    rights_from_group_lists(fixture)
    service_configuration(fixture)
    if args.admin:
        add_admin(fixture, compose, args)
    path = fixture / 'compose.json'
    path.write_text(json.dumps(compose, indent=2) + '\n')
    subprocess.run([str(compose_bin), '-p', args.project, '-f', str(path), 'config', '--quiet'], check=True)
    print(path)


if __name__ == '__main__':
    main()
