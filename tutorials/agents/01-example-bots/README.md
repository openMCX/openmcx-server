# Agent Tutorial 1: the example bots of mcx-agent (chat, voice and video)

End-to-End Tutorial 1's system and phones, plus an **agent**: an MC user that is a program. `bots` is that user. It
runs [mcx-agent](https://github.com/openMCX/openmcx-client/tree/main/agent), the plumbing that lets a program take
part in mission critical communication: mcx-agent runs the MC client `mcx-client` as the user's device and offers its
services as tools over MCP (the Model Context Protocol).

Three example bots use those tools. Each is a short Python program with nothing of OpenMCX inside:

- the **chat bot** (MCData): it marks each message read and answers `time`, `ping` and `help`;
- the **voice bot** (MCPTT): in a private call to `bots`, or a group call of its groups, it plays back what you said,
  after a short tone;
- the **video bot** (MCVideo): it shows a test card in every video call `bots` is in, as a drone or a robot would show
  its camera.

Alice and Bob talk to them on their Android phones: they write to `bots`, call it, and video call it.

<p align="center"><img src="images/architecture.svg" width="900" alt="Agent Tutorial 1: the phones of Alice and Bob reach tutorial 1's OpenMCX system over the Wi-Fi; on the computer, the agent bots (mcx-agent and its MC client) reaches the system the same way, and the chat, voice and video bots reach the agent over MCP on 127.0.0.1:8765"></p>

The agent reaches the system the way the phones and the dispatcher of End-to-End Tutorial 2 do: through `HOST_IP` and
the ports tutorial 1 publishes. It activates from MCX Admin like a phone.

> **The agent makes no calls.** It answers the calls users make to it and joins the group calls of its groups; it
> sends messages only to users who wrote to it. The bots reach only mcx-agent, on 127.0.0.1, with its token.

## What you need

- **Tutorial 1 done**: its system running, the phones activated as `alice` and `bob` in the group `operations`.
- **Docker** with Docker Compose v2 on tutorial 1's computer (or another computer on the same network, see the end).
- **The agent's image**, built from a checkout of [openmcx-client](https://github.com/openMCX/openmcx-client) (it is
  not on Docker Hub yet). From the root of the checkout:

  ```bash
  linux/tools/build-image -t openmcx-client:local
  docker build -t openmcx-agent:local --build-arg CLIENT_IMAGE=openmcx-client:local agent
  ```

  `openmcx-agent:local` holds mcx-agent, its engine `mcx-client` and the three bots
  (`/usr/local/share/mcx-agent/examples/`).

## How an agent is put together

| Part | What it is | Here |
|---|---|---|
| The MC user | A user with MCPTT, MCData and MCVideo, created in MCX Admin as for a phone | `bots`: `sip:bots.mcptt@mcx.test`, `sip:bots.mcdata@mcx.test`, `sip:bots.mcvideo@mcx.test` |
| mcx-agent | A daemon that runs `mcx-client` as the user's device and turns its services into tools: `wait_message`, `reply_message`, `wait_speech`, `speak`, `video_status`, ... ([API.md](https://github.com/openMCX/openmcx-client/blob/main/agent/API.md)). It enforces the rules: whom it may write to, how often, which services are on | container `openmcx-agent`, `setup/agent.json` |
| MCP over HTTP | The tools as an MCP server on `http://127.0.0.1:8765/mcp`, with a bearer token; pictures to show go to `POST /video` on the same port (raw I420) | the token in the agent's volume |
| The bots | Programs that call the tools: an AI agent puts a model where they answer with fixed rules | containers `chat-bot`, `voice-bot`, `video-bot` |

What each bot does with the tools:

| Bot | Loop | Tools |
|---|---|---|
| `chat-bot.py` | Wait for a message, mark it read, answer it in the sender's conversation | `status`, `wait_message`, `mark_read`, `reply_message` |
| `voice-bot.py` | Wait for a talk burst (a WAV of what was said); answer in the same call: a tone, then the speech | `status`, `call_status`, `wait_speech`, `speak` |
| `video-bot.py` | Stream pictures to `POST /video`; whenever the agent is in a video call, ask to transmit | `status`, `video_status`, `video_transmit` |

## 1. Set the addresses

```bash
cd tutorials/agents/01-example-bots
cp .env.example .env
```

In `.env`, set `HOST_IP` to the address of tutorial 1's computer (the same as in tutorial 1's `.env`). On another
computer, also set `AGENT_IP` to that computer's own address on the network; on tutorial 1's computer, leave it empty.

## 2. Create the user bots

In MCX Admin (`https://HOST_IP:8446/`, as in tutorial 1; sign in as `admin` with the password from tutorial 1's
`config/ADMIN.txt`), open **Users** → **New user**:

- **Login**: `bots`
- **Template**: `phone-user`: private calls and video calls from any user, messages from any user
- **Groups**: `sip:operations@mcx.test`, so that the bots are in the group calls of `operations`
- **Services**: tick **MCData** and **MCVideo**

Choose **Create user**, then **Password link** on its row, and set its password in the browser.

## 3. Activate the agent

1. In MCX Admin, open **Activation**, choose `bots` and **Issue link**, then **Copy link**.
2. On the agent's computer, run the activation with the link, and type the password of `bots` when asked:

   ```bash
   docker compose run --rm activate 'https://HOST_IP:8446/activate/...'
   ```

   ```
   Password of the user bots:
   activated as sip:bots@mcx.test
   ```

The agent's MC client activates as a phone does: it checks MCX Admin's certificate against the link's pin, takes the
system's settings, trust root and addresses from the package, signs in, and gets its SIP credential and device
certificate. It keeps the activated configuration in the agent's volume, with a refresh token from the IdMS instead of
the password. The activation also makes the token the bots use to reach the agent.

## 4. Start the agent and the bots

```bash
docker compose up -d
docker compose logs chat-bot voice-bot video-bot
```

Within half a minute the agent has registered, and each bot says it is ready:

```
chat-bot-1   | ready as sip:bots.mcdata@mcx.test, alias none
voice-bot-1  | voice bot ready as sip:bots.mcptt@mcx.test
video-bot-1  | video feed ready: 320x240 at 15/s
```

The agent's own view, through its command line:

```bash
docker exec openmcx-agent mcx-agent status
```

It shows the user's three services, each `"ready": true`. In MCX Admin, **Users** shows `bots` registered, as the
phones are.

## 5. Talk to the bots from the phones

On Alice's or Bob's phone:

- **Message**: write to `bots`: `time`, `ping`, or anything else. The answer comes within a second, in the same
  conversation: `It is 12:06 UTC on 2026-10-28.`, `pong`, or the bot's help, `I answer: time (the time in UTC), ping,
  help.` The message shows as read: the bot marked it read before answering.
- **Private call**: call `bots`. It answers at once. Hold the talk button and say something, then release it: after a
  short tone the bot says it back to you. Hang up when you are done.
- **Group call**: start a call to `operations`. The bots are a member of the group, so they are in the call; whoever
  talks, the bot answers in the group, and every phone hears it.
- **Video call**: choose **Video call** for `bots`: the bot's test card appears, with its moving bars. A video call to
  `operations` shows it to every phone in the call. Holding **Transmit** sends your camera to the others; the bot
  does not look at it.

The server limits each transmission to a set time. When it takes the transmission back, the bot asks again at once,
so the picture stops for a moment and comes back.

To see what the bots do meanwhile:

```bash
docker compose logs -f chat-bot voice-bot video-bot
```

```
chat-bot-1   | sip:alice.mcdata@mcx.test: 'time' -> 'It is 12:06 UTC on 2026-10-28.'
voice-bot-1  | heard sip:alice.mcptt@mcx.test in a private call (sip:alice.mcptt@mcx.test): 3120 ms
voice-bot-1  | spoke to sip:alice.mcptt@mcx.test: spoken (3470 ms)
voice-bot-1  | heard sip:bob.mcptt@mcx.test in a prearranged call (sip:operations@mcx.test): 2400 ms
voice-bot-1  | spoke to sip:operations@mcx.test: spoken (2750 ms)
video-bot-1  | in a private call: transmission granted
```

## 6. Stop or start over

```bash
docker compose down         # stop; the activated user is kept
docker compose down -v      # stop and forget the activation (and the agent's messages)
```

Tutorial 1's system is not affected by either. After `down -v`, activate `bots` again (step 3, with a new link). If
tutorial 1 starts over with a new system, also start the agent over (`down -v`), create `bots` again and activate it.

One user, one device: the servers accept a user's services from one device at a time. Activate `bots` on one agent
only, and do not activate it on a phone.

## Your own agent

The bots are the place for your agent. Stop a bot (`docker compose stop chat-bot`) and run your program instead,
pointing its MCP client at `http://127.0.0.1:8765/mcp` with `Authorization: Bearer <token>`. The token is in the
agent's volume:

```bash
docker compose exec -T agent cat /data/token
```

An MCP client library's streamable HTTP transport works as it is; so do Claude Code and other MCP hosts on the
agent's computer:

```bash
claude mcp add --transport http mcx http://127.0.0.1:8765/mcp --header "Authorization: Bearer $(docker compose exec -T agent cat /data/token)"
```

The tools, their results and error codes are in
[API.md](https://github.com/openMCX/openmcx-client/blob/main/agent/API.md), and the bots' sources in
[agent/examples](https://github.com/openMCX/openmcx-client/tree/main/agent/examples). The chat bot step by step is
[FIRST_AGENT.md](https://github.com/openMCX/openmcx-client/blob/main/agent/FIRST_AGENT.md). The agent's rules
(`setup/agent.json`) are in mcx-agent's [README](https://github.com/openMCX/openmcx-client/blob/main/agent/README.md).

## When something does not work

- **`pull access denied for openmcx-agent`**: build the image first (What you need).
- **The activation fails**: the link works once and expires; issue a new one. `the activation URL was refused` is a
  used or expired link; a sign-in error is a wrong password.
- **A bot keeps "waiting"**: `docker compose logs <bot>` says what for, e.g. `waiting for mcvideo: ...` while the
  agent is not yet signed in. `docker exec openmcx-agent mcx-agent status` shows each service, with `last_error`, and
  `docker compose logs agent` the engine's events.
- **The bots do not answer the phones**: check that `bots` is registered in MCX Admin and in the group `operations`,
  and that the phones write to and call `bots`, not another user.
- **Calls connect but the bot is not heard, or the video stays black**: the agent's UDP ports (below) are blocked on its
  computer.

## How it is put together

- **The agent** (`docker-compose.yaml`) runs on the network of its computer, as a phone is on the Wi-Fi. Its device
  settings (`setup/device.json.in`, with the two addresses filled in at activation) hold only local settings: ports
  and addresses. Everything else comes from the activation (`setup/activate.sh` runs `mcx-client --activate`). As for
  the dispatcher of tutorial 2, three settings make it work on tutorial 1's own computer as well as on another one:
  `sip.outbound` (the SIP core reaches it over the connection it registered on), `media.server_source: "port"` (the
  servers' media is accepted from the negotiated port whatever address Docker's NAT shows) and `media.bind` on
  `AGENT_IP`.
- **mcx-agent** (`setup/agent.json`): voice and video on, pictures of 320x240 at 15 per second, no recipient list (it
  answers only users who wrote to it in the last 24 hours), rate limits, and MCP over HTTP on 127.0.0.1:8765. It runs
  the activated engine with the settings an agent needs: it answers calls at once, hands each talk burst to the voice
  bot, and takes the video bot's pictures in place of a camera.
- **The bots** run from the same image, on the computer's network, and reach only 127.0.0.1:8765 with the token.

Ports on the agent's computer, none of which tutorial 1 or the dispatcher of tutorial 2 uses, so all three run on one
computer: 5081/tcp (SIP), 4800 and 5800/udp (speech and floor control), 4900, 5900 and 6900/udp (MCVideo), and
8765/tcp on 127.0.0.1 only (MCP).

## Running the agent on another computer on the network

Copy this folder to the other computer (or check out the repository there), build the image there, set `HOST_IP` to
tutorial 1's computer and `AGENT_IP` to the other computer in `.env`, and activate and start it as in steps 3 and 4.
Nothing is copied from tutorial 1's computer: the activation link and the password of `bots` are enough. The two
computers must reach each other (no firewall between them for the ports tutorial 1 publishes and the agent's ports
above).

Checked on 2026-10-28 with the agent on tutorial 1's own computer, activated from MCX Admin: messages, private and group
calls, and private and group video calls with the bots, from a client activated as Alice the same way.
