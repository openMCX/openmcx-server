#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise the running standalone lab and retain quantitative speech evidence.

A prearranged group call between client-a and client-b (TS 24.379 clause 10.1.1) with clear media and floor control:
the first talker is granted the floor, the second is denied it while the floor is taken (TS 24.380 clause 6.3.5.4.4,
Floor Deny), each talker's AMR-WB speech is received and decoded by the other, and the call is torn down. The decoded
audio of each client must be at least one second long and not silent.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import array
import json
import math
import pathlib
import subprocess
import time
import wave

ROOT = pathlib.Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / 'artifacts'


# ------------------------------------------------------------------------------
def command(client, text):
    """Run one mcx-client command in the client's container of the standalone lab."""
    subprocess.run(
        [
            str(ROOT / 'tools/mcx'),
            'compose',
            'exec',
            '-T',
            client,
            'mcx-client',
            '--config',
            f'/config/{client}.json',
            '--command',
            text,
        ],
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


# ------------------------------------------------------------------------------
def status(role):
    """The role's status.json, or an empty dict while it is missing or half written."""
    try:
        return json.loads((ARTIFACTS / role / 'status.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ------------------------------------------------------------------------------
def wait(label, predicate, timeout=30):
    """Poll predicate every 0.1 s until it returns a true value (returned) or timeout seconds pass (raise)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(
        f'{label} timed out: ' + json.dumps({role: status(role) for role in ('client-a', 'client-b', 'mcptt-server')})
    )


# ------------------------------------------------------------------------------
def audio(path):
    """Length, RMS and peak of a received 16 kHz mono PCM16 wav; fail if shorter than 1 s or silent."""
    with wave.open(str(path), 'rb') as wav_file:
        assert (wav_file.getnchannels(), wav_file.getsampwidth(), wav_file.getframerate()) == (1, 2, 16000)
        samples = array.array('h', wav_file.readframes(wav_file.getnframes()))
    assert len(samples) >= 16000, 'less than one second of received audio'
    rms = math.sqrt(sum(sample * sample for sample in samples) / len(samples))
    assert rms > 100, 'decoded audio is silent'
    return {
        'samples': len(samples),
        'seconds': len(samples) / 16000,
        'rms': round(rms, 2),
        'peak': max(abs(sample) for sample in samples),
    }


# ------------------------------------------------------------------------------
def main():
    """Run the two-way speech call and write integration/speech-results.json."""
    transport = status('mcptt-server').get('sip_transport', 'tls')
    result = {
        'scenario': 'prearranged-group-two-way-AMR-WB',
        'security_profile': f'explicit clear media/floor lab; SIP {transport}; HTTPS common services',
        'checks': {},
    }
    wait(
        'both clients affiliated',
        lambda: all(status(client).get('affiliated') for client in ('client-a', 'client-b')),
        60,
    )
    assert len(status('mcptt-server').get('participants', [])) == 0, 'start with an idle lab'
    command('client-a', 'call')
    wait(
        'two active call legs',
        lambda: (
            all(status(client).get('call_state') == 'active' for client in ('client-a', 'client-b'))
            and len(status('mcptt-server').get('participants', [])) == 2
        ),
    )
    result['checks']['group_call'] = True
    initial_b = status('client-b').get('received_packets', 0)
    initial_denials = status('client-b').get('floor_denials', 0)
    command('client-a', 'ptt /artifacts/speech/alpha.wav')
    wait('alpha floor grant', lambda: status('client-a').get('talking'))
    command('client-b', 'ptt /artifacts/speech/bravo.wav')
    wait('bravo contention denied', lambda: status('client-b').get('floor_denials', 0) > initial_denials)
    result['checks']['single_talker_contention'] = True
    wait('alpha speech delivered', lambda: status('client-b').get('received_packets', 0) >= initial_b + 100)
    wait(
        'alpha floor release',
        lambda: not status('client-a').get('talking') and not status('mcptt-server').get('floor_owner'),
    )
    initial_a = status('client-a').get('received_packets', 0)
    command('client-b', 'ptt /artifacts/speech/bravo.wav')
    wait('bravo floor grant', lambda: status('client-b').get('talking'))
    wait('bravo speech delivered', lambda: status('client-a').get('received_packets', 0) >= initial_a + 100)
    wait(
        'bravo floor release',
        lambda: not status('client-b').get('talking') and not status('mcptt-server').get('floor_owner'),
    )
    command('client-a', 'hangup')
    wait(
        'call teardown',
        lambda: (
            all(status(client).get('call_state') == 'idle' for client in ('client-a', 'client-b'))
            and not status('mcptt-server').get('participants')
        ),
    )
    result['audio'] = {client: audio(ARTIFACTS / client / 'received.wav') for client in ('client-a', 'client-b')}
    result['checks']['two_way_decoded_speech'] = True
    result['checks']['teardown'] = True
    result['status'] = {role: status(role) for role in ('client-a', 'client-b', 'mcptt-server')}
    result['passed'] = True
    out = ARTIFACTS / 'integration'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'speech-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
