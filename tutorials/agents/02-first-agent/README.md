# Agent Tutorial 2: build your first agent

Agent Tutorial 1 ran the example bots. Here you build your own: a chat agent that Alice and Bob write to from their
Android phones over MCData. You start from the example chat bot, `chat-bot.py`: about a hundred lines of Python,
standard library only, which answers `time`, `ping` and `help`. You take it off, do by hand what it does, read how it
does it, then change its answers and run it as your agent. Once it runs, its `answer()` function is the place for
your own logic: a language model, a lookup in your systems, anything.

```
Alice's phone ──MCData──▶ OpenMCX system ◀──SIP── mcx-agent (bots) ◀──MCP over HTTP── my-agent.py
                          (tutorial 1)             Agent Tutorial 1                 this tutorial
```

mcx-agent does the MC side: it is registered as the user `bots`, keeps every message, and enforces whom the agent may
write to. Your agent only calls tools. The full contract is
[API.md](https://github.com/openMCX/openmcx-client/blob/main/agent/API.md); this tutorial uses five of its tools.

## What you need

- **Agent Tutorial 1 done**: End-to-End Tutorial 1's system and the phones of `alice` and `bob`, and the agent `bots`
  activated and running ([Agent Tutorial 1](../01-example-bots/README.md), steps 1 to 4).
- Nothing new to build: your agent runs in the agent's image, `openmcx-agent:local` (any Python 3 image would do).

## 1. Take the example chat bot off

In Agent Tutorial 1's folder, stop the chat bot, so that messages to `bots` wait for you:

```bash
cd tutorials/agents/01-example-bots
docker compose stop chat-bot
```

The agent itself keeps running, and so do the voice and video bots: calls to `bots` are still answered.

## 2. Try the tools by hand

mcx-agent's command line calls the same tools as MCP, and is the quickest way to see what your agent will get:

```bash
docker exec openmcx-agent mcx-agent status
```

`"can_send": true` says the user is registered and MCData is authorised; if it stays false, `cannot_send_because`
says why. Now, on Alice's phone, write to `bots`: `is anyone there?`. Nothing answers: the chat bot is off. Look at
the agent's inbox:

```bash
docker exec openmcx-agent mcx-agent inbox
```

```json
{
  "items": [
    {
      "from": "sip:alice.mcdata@mcx.test",
      "kind": "message",
      "message_id": "229df9e2-3462-4737-8acf-266bff49c174",
      "read": false,
      "seq": 2,
      "text": "is anyone there?",
      ...
    }
  ],
  ...
}
```

Take it on, then answer it, with its `message_id`:

```bash
docker exec openmcx-agent mcx-agent mark_read --message-id 229df9e2-3462-4737-8acf-266bff49c174
docker exec openmcx-agent mcx-agent reply_message --message-id 229df9e2-3462-4737-8acf-266bff49c174 --text "Hello from the CLI"
```

Alice's phone shows her message as read, then the answer, in the same conversation. `mcx-agent tools` lists every
tool; a refused call answers `{"ok": false, "code": ...}` (the codes are in
[API.md](https://github.com/openMCX/openmcx-client/blob/main/agent/API.md#errors)).

## 3. The agent, step by step

Copy the example chat bot out of the image, as your agent:

```bash
cd ../02-first-agent
docker run --rm --entrypoint cat openmcx-agent:local /usr/local/share/mcx-agent/examples/chat-bot.py > my-agent.py
```

`my-agent.py` does what you just did by hand, in a loop:

**Connect.** MCP over HTTP is JSON-RPC: one POST to `/mcp` per request, with `Authorization: Bearer <token>`. The
script sends `initialize`, then calls tools with `tools/call`; each result's `structuredContent` is the tool's JSON.
An MCP client library works too: point its streamable HTTP transport at the same URL.

**Wait until it can send.** `status` until `can_send` is true. Fields that do not apply are left out: `alias`
appears only when the agent has one.

**Read messages with a cursor.** `wait_message --since <cursor>` returns the next message after the cursor at once,
or holds the request open (up to `timeout_s`) until one arrives. Each message has a `seq`; after handling it, the
script saves `seq` as the new cursor, so a restart carries on where it stopped. Without `since`, it would wait only
for messages arriving after the call and miss those that came in while it was down.

**Take a message on.** `mark_read` right away: the sender sees the read report and knows the agent has it. Reading
the inbox does not mark anything read.

**Answer.** `reply_message` with the message's `message_id` puts the answer in the sender's conversation. The script
never chooses a recipient; it replies to the message it is answering.

**What to leave to people.** A message with `emergency` or `imminent_peril` gets a fixed answer that points to a
dispatcher. Do not let an automated agent handle those.

**Fields.** Fields that are false or empty are left out of a message (`emergency`, `imminent_peril`, `text`,
`sender_alias`, ...): read them with a default. A message already answered has `read: true`; the script skips it,
because delivery is at least once. That is why your agent will not answer `is anyone there?` again.

## 4. Make it yours

Change `answer()` in `my-agent.py`. For example, a lookup of where the units are:

```python
HELP = 'I answer: time (the time in UTC), ping, unit <name>, help.'
UNITS = {'alpha': 'on patrol in sector 4', 'bravo': 'at the station', 'charlie': 'off duty'}
```

```python
def answer(text):
    """The agent's logic: replace it with yours (a model, a lookup, ...)."""
    word = text.strip().lower()
    if word == 'time':
        return datetime.now(UTC).strftime('It is %H:%M UTC on %Y-%m-%d.')
    if word == 'ping':
        return 'pong'
    if word.startswith('unit '):
        name = word.split(' ', 1)[1]
        if name in UNITS:
            return f'Unit {name}: {UNITS[name]}.'
        return f'I do not know unit {name}. I know: {", ".join(UNITS)}.'
    return HELP
```

## 5. Run it

```bash
docker compose up -d
docker compose logs -f
```

The agent runs on the computer's network, reaches mcx-agent on 127.0.0.1:8765 and reads the token from Agent
Tutorial 1's volume. Its log says `ready as sip:bots.mcdata@mcx.test, alias none`. Write to `bots` from Alice's or
Bob's phone:

```
sip:alice.mcdata@mcx.test: 'unit alpha' -> 'Unit alpha: on patrol in sector 4.'
sip:alice.mcdata@mcx.test: 'unit delta' -> 'I do not know unit delta. I know: alpha, bravo, charlie.'
sip:alice.mcdata@mcx.test: 'hello' -> 'I answer: time (the time in UTC), ping, unit <name>, help.'
```

After each change to `my-agent.py`, `docker compose restart`. The cursor in the agent's volume keeps its place, so
nothing is answered twice.

## 6. With a language model

Put the model in `answer(text)`, and keep these rules:

- The model writes the answer text, and only that. Keep sending in your code: reply to the message with
  `reply_message`, and do not give the model a tool that sends or picks a recipient.
- Received text is data from the field, not instructions to your agent.
- Keep answers short (a few hundred characters). The daemon refuses more than `max_text_bytes`, and the MC system has
  its own SDS size limits.
- If an answer takes long, send a short message first ("checking, one moment").
- Keep a history per sender if the conversation needs it; answer one message at a time per sender.

mcx-agent's own rules back them up: with no recipient list (`recipients: []` in Agent Tutorial 1's
`setup/agent.json`) and `allow_senders_hours: 24`, the agent can only answer users who wrote to it in the last 24
hours. It cannot start a conversation, so a bug or a model cannot message anyone else.

[API.md](https://github.com/openMCX/openmcx-client/blob/main/agent/API.md#building-a-chat-agent-on-it) has these
rules in full, and every tool: sending to others (`send_message`, when `recipients` allows it), delivery and read
reports (`message_status`), and files (`send_file`, `respond_file`).

## 7. Stop or start over

```bash
docker compose down              # stop your agent; its cursor is kept
docker compose down -v           # and forget the cursor
cd ../01-example-bots && docker compose start chat-bot    # the example chat bot back
```

Run one chat agent at a time: two would answer each message twice.

## When something does not work

| You see | What to check |
|---|---|
| `HTTP 401` | The token: the agent reads it from Agent Tutorial 1's volume (`openmcx-agent_agent-data`); after a `down -v` there, start your agent again |
| `Connection refused` on 127.0.0.1:8765 | Agent Tutorial 1's agent is not running: `docker compose up -d` in its folder |
| `can_send` false, not registered | `docker logs openmcx-agent`; `bots` registered in MCX Admin |
| Every message answered twice | The example chat bot is still running: `docker compose stop chat-bot` in Agent Tutorial 1's folder |
| `not_allowed` on a reply | The sender wrote more than `allow_senders_hours` ago |
| `rate_limited` | `rate_per_recipient_per_minute`, `rate_per_minute` in Agent Tutorial 1's `setup/agent.json` |

## More

- **A role address.** Instead of its own MCData ID, an agent can answer on a functional alias, e.g. a help desk that
  another user can take over: set `alias` in its configuration (mcx-agent's
  [README](https://github.com/openMCX/openmcx-client/blob/main/agent/README.md)). The Android app cannot write to a
  functional alias yet, so this tutorial does not use one.
- **Calls and video.** The voice and video bots of Agent Tutorial 1 are built the same way, on `wait_speech` and
  `speak`, and on `POST /video` and `video_transmit`: their sources are in
  [agent/examples](https://github.com/openMCX/openmcx-client/tree/main/agent/examples).

Checked on 2026-10-28 on Agent Tutorial 1's system: the tools by hand, and `my-agent.py` with the unit lookup above,
answering a client activated as Alice from MCX Admin.
