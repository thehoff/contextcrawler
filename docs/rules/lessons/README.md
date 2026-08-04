# lessons/ — unratified candidates

Same split as `askew.devRules`: `../RULES.md` is ratified law, this directory is
the inbox.

**Write a lesson the moment a fix is confirmed**, not at the end of the session
and not "later". The cost of a lesson is five minutes now; the cost of not
writing it is the same bug again in three months, which this repo has already
paid more than once.

## What earns a lesson

- A quirk that cost real time and will recur
- A bug whose *class* is likely to repeat, not just this instance
- A wrong assumption that survived review
- A measurement that turned out to be misleading

## What does not

- One-off typos
- Anything already covered by a `CTX-` rule (cite the rule instead)
- Restating what the code already says plainly

## Promotion

Do **not** promote a lesson into `RULES.md` yourself. Ratification is the
Hoff's manual step, exactly as in `askew.devRules`. A ratified rule earns a
`CTX-` number and, wherever a machine can check it, a test in
`tests/ctxcrl_rules.rs`.

A rule that cannot fail a test is a REVIEW rule and belongs on the pre-merge
checklist — be honest about which kind you are proposing.
