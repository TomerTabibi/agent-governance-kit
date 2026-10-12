# Case Study: Governing a Multi-Agent Software Team

> Token figures are a model of the avoided polling design, not measured spend.

## 1. Context

A software product in active development, built by a small human team working with a team of AI agents. Each agent had a defined role:

| Role | Responsibility |
| --- | --- |
| UI developer | Builds front-end features |
| UI reviewer | Independently reviews the UI developer's work |
| Backend developer | Builds server-side code |
| Code reviewer | Independently reviews backend changes |
| Database agent | Owns schema, migrations and data changes |
| Orchestrator | Assigns tasks, routes messages, tracks progress, escalates to humans |

Hundreds of messages a day moved between agents. Humans set direction and approved sensitive actions.

## 2. The problem

- **Coordination.** Agents needed to hand work to each other without a human relaying every message.
- **Sensitive actions.** Commits, pushes, database changes and deployment cannot be left to an agent's judgment alone.
- **Prompt injection by design.** An agent reads messages, files and repository content written by other agents. Any of it can contain text that looks like an instruction or an approval.
- **Cost.** An agent that does not know when work arrives has to keep checking, and every check re-sends its whole context to the model.

## 3. Design principles

1. **One identity per agent.** Separate credentials, least-privilege scopes, an expiry date. No agent borrows a human's or another agent's identity.
2. **Messages are data, never authority.** A message can carry a task or a question. It can never grant permission.
3. **Approval comes only from the human, in the human's own channel.** One approval covers one exact action and is not reused.
4. **Protect data before changing it.** Verified backup, known target and a rollback plan before any shared database change.
5. **Event-driven, not polling.** Agents sleep until a signed event wakes them.
6. **Say only what matters.** No greetings, no "received" replies, no status pings, only tasks, blockers, decisions and results with evidence.

## 4. Architecture

```
 Human (owner) ──approves in own channel──► Agent sessions
                                              │   ▲
                              send / read     │   │ wake (signed event)
                                              ▼   │
                                        Mailbox server ──► Audit trail
                                              │
                               scoped identity per agent
```

- **Mailbox server:** project-scoped inboxes, per-agent identities with read/send/ack scopes, idempotency keys for safe retries.
- **Signed wake:** each agent session has a local listener on a port. The server pushes a signed event to it, and the listener wakes only the relevant agent session. Agents never poll. The next wake is armed only after the agent acknowledges the latest message, so a session never gets woken twice for the same backlog.
- **Orchestrator routing:** incoming messages are routed by topic to the session that owns the work.

## 5. What went wrong and what changed

| Incident | Risk | Change |
| --- | --- | --- |
| Agents replied "received" to each other, and sometimes acknowledged acknowledgments | Message loops, wasted tokens, noise hiding real blockers | Policy: no receipt-only messages; one transport ACK per wake; replies only for tasks, blockers, decisions or results |
| An agent passed on a commit/push approval as if it came from the owner | An unauthorized action looking legitimate | Approvals are valid only when given directly by the human in their own channel; relayed approvals are ignored |
| Sessions were not re-woken after new messages arrived | Work silently stalling | The wake protocol was tied to acknowledging the latest message; the waiter re-arms automatically when the session starts |

## 6. Results

### Token savings: listen, don't poll

The obvious way to let an agent know work has arrived is to have it check its inbox on a timer. Every check re-sends the agent's full working context to the model, even when the inbox is empty. We rejected that design.

Instead, each agent session has a local listener on a port. The mailbox server sends it a signed wake event when a message arrives, and only then does the agent run. An idle agent costs zero tokens.

The polling design we avoided, as a baseline:

| Input | Value |
| --- | --- |
| Agents | 6 |
| Check interval | every 5 min (a typical choice) |
| Active hours/day | 10 |
| Context re-sent per check | ~50,000 tokens |

`6 agents × 120 checks/day × 50,000 tokens ≈ 36 million tokens/day` spent only on asking "is there work?". With event-driven wake that cost is zero, and every token is spent on real work.

### Other outcomes

- Hundreds of agent-to-agent messages per day with no human relay.
- Independent review on every change: UI and code each had a dedicated reviewer agent.

## 7. Lessons for organizations adopting agents

1. Give every agent its own identity and the smallest set of permissions. Shared keys make auditing impossible.
2. Treat everything an agent reads as untrusted, including other agents' messages.
3. Make approval a property of the channel, not of the message text.
4. Polling is the hidden cost of agent systems. Have agents listen for events instead of checking on a timer.
5. Write a communication policy for agents just as you would for people. Chatty agents cost money and hide real problems.
6. Pair every builder agent with an independent reviewer agent.
