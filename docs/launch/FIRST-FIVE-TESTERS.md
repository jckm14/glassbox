# Recruit Glassbox's first five testers

Prepared launch copy, not a record of published posts, recruited testers, or
existing sponsors. Use after the example has merged into the default branch.

## Public invitation

I’m looking for five developers who run AI agents that edit files on Linux.

I built Glassbox because I wanted a clear record of what an agent changed—and a
way to check whether undoing one edit would overwrite newer work.

There’s now a small runnable example: a demo tool edits a disposable file,
Glassbox records it, and a confirmed rollback restores it. Then the example adds
a newer edit and checks that rollback is refused with HTTP 409.

It runs locally without a model or API key. Glassbox is Apache-2.0, Linux-only
alpha software. Integrations must submit actions explicitly; it doesn’t intercept
tools automatically. The example uses the real API in-process, not a named
framework integration.

If you have a few minutes to try it, I’d like to know which agent you use and
where this would fit—or fail to fit—your workflow.

Try it: https://github.com/jckm14/glassbox/tree/main/examples

Feedback: https://github.com/jckm14/glassbox/issues/8

If it helps your work, you can support maintenance and security-focused testing:
https://github.com/sponsors/jckm14

## Thirty-second walkthrough

Use only the disposable example. Keep the Linux alpha label on screen. This is a
recording script; no new video is included. The existing dashboard walkthrough is
available at [walkthrough.gif](../assets/launch/walkthrough.gif).

| Time | Show | Say |
| --- | --- | --- |
| 0–6s | Example source: the write followed by receipt submission | “An agent tool changes a file. This hook records what happened in Glassbox.” |
| 6–15s | Run the example; highlight steps 1 and 2 | “For this eligible text-file edit, a confirmed rollback restores the original bytes.” |
| 15–23s | Highlight step 3 and the newer-edit code | “If someone edits it afterward, rollback is refused. The newer text stays.” |
| 23–30s | Step 4, repository URL, Linux alpha label | “History remains verifiable. I’m looking for five Linux agent developers to try the example.” |

## First-week execution

1. Merge the working example and share the public invitation on your own profile.
2. Share the existing GIF alongside it. Check any community's current promotion
   rules before posting there; adapt the invitation to its audience.
3. Invite relevant developers who have already shown interest. Read their public
   project first, and explain the specific connection. Do not mass-message stars
   or assume a star means someone uses Glassbox.
4. Ask testers the four questions in the example README. Track only consented,
   useful feedback; do not publish identities or quotations without permission.
5. Fix the most common onboarding obstacle, publish a short update with actual
   results, and invite satisfied users to sponsor maintenance.

Success for week one means five attempted trials and a concrete understanding of
the main integration obstacle. It is a target, not a claim or a revenue forecast.
Track trial attempts, successful runs, useful feedback, repeat use, and voluntary
sponsorship separately. Leave counts empty until observed.

## Sponsor follow-up after a useful trial

Thanks for trying Glassbox and sharing your feedback. If it is useful to your
workflow, would you consider sponsoring its maintenance? Support helps me spend
time on bug fixes, security-focused testing, documentation, and integration
examples. There’s no obligation, and feedback is welcome either way.

https://github.com/sponsors/jckm14

## Progress update outline

Report what shipped, what testers actually encountered, what changed because of
their feedback, and what comes next. Include the sponsor link once. Use measured
counts only, and obtain permission for any names, logos, or quotes.
