#!/usr/bin/env python3
"""A client must reauthorize and reaffiliate without restarting the server.

After client-a's container restarts (a new client instance), it registers and is authorised again (TS 24.379 clause
7.2.1) and affiliates again (TS 24.379 clause 9.2.1.2), while the server instance and client-b's affiliation are
unchanged.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import json
import subprocess
from speech_scenario import ROOT, ARTIFACTS, status, wait


# ------------------------------------------------------------------------------
def main():
    """Restart client-a, wait for its reauthorization and reaffiliation and write integration/restart-results.json."""
    wait('initial affiliations', lambda: all(status(role).get('affiliated') for role in ('client-a', 'client-b')))
    old = status('client-a').get('instance_id')
    server = status('mcptt-server').get('instance_id')
    assert old and server, 'run binaries containing instance identifiers'
    subprocess.run([str(ROOT / 'tools/mcx'), 'compose', 'restart', 'client-a'], check=True, cwd=ROOT)
    wait(
        'client reauthorization after restart',
        lambda: status('client-a').get('instance_id') != old and status('client-a').get('affiliated'),
        60,
    )
    assert status('mcptt-server').get('instance_id') == server, 'server unexpectedly restarted'
    assert status('client-b').get('affiliated'), 'other client lost affiliation'
    result = {
        'passed': True,
        'client_instance_changed': True,
        'server_instance_unchanged': True,
        'reauthorized': status('client-a').get('authorized'),
        'reaffiliated': True,
    }
    (ARTIFACTS / 'integration' / 'restart-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
