# Benchmark corpora

Input/behavior corpora are included so you can reproduce the input & behavior
numbers with `python -m neosguard.guard_eval`.

The **output** leak corpora (`guard_output_corpus.json`, `guard_output_holdout.json`)
are intentionally **omitted** from this public repo: they are test fixtures full of
secret-*format* strings (fake Stripe/AWS/OpenAI keys, etc.) used to exercise the
leak detector, and committing secret-format strings to a public repo is bad practice
(every secret scanner flags them). The computed output metrics live in
`guard_report.json`. To reproduce them locally, generate your own fixtures with
`neosguard.guard_redteam.generate_leak_attacks()` or add your own.
