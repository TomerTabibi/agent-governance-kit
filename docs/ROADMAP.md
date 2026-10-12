# Roadmap

## Done

- Agent and human identities: signed, scoped, expiring, revocable tokens. Agents can never hold the approval scope.
- Mailbox: scoped send/read/ack, idempotent sends, no receipt-only messages, one wake per backlog.
- Approval gate: one human approval for one exact action, used once by its requester.
- Hash-chained audit trail with tamper detection.
- Signed, timestamped, replay-protected wake events over a local port. Agents never poll.
- End-to-end demo and unit tests, with CI on Linux and Windows.

## Next

1. **LLM agent adapter.** Let a real model drive an agent role behind the same gates. The default demo stays offline; live mode is opt-in with the user's own API key.
2. **Persistent state.** Store approval requests and wake state durably, so a restart loses nothing.
3. **Approval channel.** A real human approval surface (CLI or web) separate from the agents' process.
4. **Policy file.** Declare sensitive actions and per-agent scopes in configuration instead of code.
5. **Business demo.** A policy Q&A agent with citations, access control and a time-saved metric.
