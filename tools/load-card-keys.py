#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#
"""Put the K, OPc and AMF of card-backed IMS AKA subscriptions into a running SIP database.

tools/provision.py writes such a subscription ("card": ICCID in the lab description) without its keys: they stay in
the operator's owner-only key file and reach only the SIP database, which takes the place of the HSS/AuC that holds
them (TS 33.102 clause 6.3.2). This tool reads the key file, keeps the rows of the cards the lab names (cards.json of
the generated configuration) and sends one UPDATE per card to the database's client inside the sip-db container,
on its standard input: no key appears on a command line, in a file or in a log.

    tools/load-card-keys.py --card-keys ~/.openmcx-secrets/cards.csv --cards config/generated/cards.json \\
        --container <sip-db container> [--domain mcx.test]

The key file is a CSV with at least the columns iccid, imsi, ki and opc (32 hexadecimal digits each), and optionally
amf (4 hexadecimal digits; otherwise 8000). It must be readable by its owner only.
"""
import argparse
import csv
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

HEX = {"ki": 32, "opc": 32, "amf": 4}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--card-keys", type=pathlib.Path, required=True)
    parser.add_argument("--cards", type=pathlib.Path, required=True, help="cards.json of the generated configuration")
    parser.add_argument("--container", required=True, help="the running sip-db container")
    parser.add_argument("--domain", default="mcx.test")
    args = parser.parse_args()

    # The key file is refused unless only its owner can read or write it (checked on the open descriptor).
    with args.card_keys.open(newline="") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            sys.exit(f"{args.card_keys}: readable or writable by others; chmod 600 it")
        rows = {row["iccid"]: row for row in csv.DictReader(handle)}
    wanted = json.loads(args.cards.read_text())
    statements = []
    for role, iccid in wanted.items():
        row = rows.get(iccid)
        if row is None:
            sys.exit(f"card {iccid} of {role} is not in {args.card_keys}")
        values = {"amf": row.get("amf") or "8000", "ki": row["ki"], "opc": row["opc"]}
        for name, length in HEX.items():
            if not re.fullmatch(f"[0-9a-fA-F]{{{length}}}", values[name]):
                sys.exit(f"card {iccid}: {name} must be {length} hexadecimal digits")
        if not re.fullmatch(r"[0-9]{6,15}", row["imsi"]) or not re.fullmatch(r"[a-zA-Z0-9.-]+", args.domain):
            sys.exit(f"card {iccid}: invalid IMSI or domain")
        statements.append(
            f"UPDATE ims_subscription SET k=UNHEX('{values['ki']}'), opc=UNHEX('{values['opc']}'), "
            f"amf=UNHEX('{values['amf']}') WHERE impi='{row['imsi']}@{args.domain}' AND auth_scheme='aka';"
            # ROW_COUNT() counts changed rows only (a second load would read 0): check the row and its key instead.
            f" SELECT COUNT(*) FROM ims_subscription WHERE impi='{row['imsi']}@{args.domain}' AND k IS NOT NULL;")
    if not statements:
        sys.exit("no card in the lab")
    result = subprocess.run(
        ["docker", "exec", "-i", args.container, "sh", "-c",
         'MYSQL_PWD="$(cat /run/secrets/mysql-password)" mysql -h 127.0.0.1 -u mcx -D mcx -N -B'],
        input="\n".join(statements) + "\n", capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"sip-db: {result.stderr.strip()}")
    counts = result.stdout.split()
    for (role, iccid), count in zip(wanted.items(), counts):
        print(f"{role}: card {iccid} {'loaded' if count == '1' else 'NOT loaded (no subscription row)'}")
    if any(count != "1" for count in counts):
        sys.exit(1)


if __name__ == "__main__":
    main()
