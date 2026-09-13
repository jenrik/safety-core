import marimo

__generated_with = "0.23.16"
app = marimo.App(width="full")


@app.cell
def _():
    from concurrent.futures import ThreadPoolExecutor
    import json
    import marimo
    import os
    import sqlite3
    import subprocess
    from pathlib import Path

    import polars as pl

    marimo.md("""
    # OpenCode Bash policy replay

    Load Bash calls already executed by OpenCode, replay their pre-execution and
    permission hooks without executing them, and compare that result with the
    recorded historical outcome. The replay uses a fresh native `ask` baseline
    and disables the LLM judge, so it never sends historical commands to a
    provider. `historical_decision` is always `allow`: the OpenCode database
    records executed tool calls, not native permission prompts denied before a
    tool call was created.
    """)
    return Path, ThreadPoolExecutor, json, marimo, os, pl, sqlite3, subprocess


@app.cell
def _(Path, marimo, os):
    default_database = Path(os.environ.get("OPENCODE_DATABASE", Path.home() / ".local/share/opencode/opencode.db"))
    database_path = marimo.ui.text(label="OpenCode SQLite database", value=str(default_database), full_width=True)
    limit = marimo.ui.number(label="Commands to replay (0 = all)", value=500, start=0, step=100)
    workers = marimo.ui.number(label="Parallel replay workers (max 32)", value=min(8, os.cpu_count() or 1), start=1, stop=32, step=1)
    marimo.vstack([database_path, limit, workers])
    return database_path, limit, workers


@app.cell
def _(Path, database_path, limit, pl, sqlite3):
    query = """
        SELECT
          part.id AS part_id,
          part.session_id,
          datetime(part.time_created / 1000, 'unixepoch') AS recorded_at,
          json_extract(part.data, '$.callID') AS call_id,
          json_extract(part.data, '$.state.input.command') AS command,
          json_extract(part.data, '$.state.status') AS historical_tool_status,
          json_extract(part.data, '$.state.metadata.exit') AS historical_exit_code,
          json_extract(part.data, '$.state.error') AS historical_error
        FROM part
        WHERE json_extract(part.data, '$.type') = 'tool'
          AND json_extract(part.data, '$.tool') = 'bash'
          AND json_type(part.data, '$.state.input.command') = 'text'
        ORDER BY part.time_created DESC
    """
    if limit.value:
        query += " LIMIT ?"

    with sqlite3.connect(f"file:{Path(database_path.value).resolve()}?mode=ro", uri=True) as connection:
        cursor = connection.execute(query, (int(limit.value),) if limit.value else ())
        rows = cursor.fetchall()
        columns = [column[0] for column in cursor.description]

    history = pl.DataFrame(
        rows,
        schema={column: pl.String for column in columns},
        orient="row",
        strict=False,
    ).with_columns(
        pl.lit("allow").alias("historical_decision"),
        pl.lit(True).alias("historically_allowed"),
        pl.lit(False).alias("historically_denied"),
    )
    return (history,)


@app.cell
def _(history):
    history
    return


@app.cell
def _(Path, ThreadPoolExecutor, history, json, pl, subprocess, workers):
    events = [{"command": command, "nativePermission": "ask"} for command in history.get_column("command").to_list()]
    replay_script = Path(__file__).parents[1] / "analysis/replay-opencode-history.ts"
    replay_rows = []
    if events:
        worker_count = max(1, min(int(workers.value), len(events), 32))
        chunk_size = (len(events) + worker_count - 1) // worker_count
        batches = [events[offset:offset + chunk_size] for offset in range(0, len(events), chunk_size)]

        def replay_batch(batch):
            completed = subprocess.run(
                ["bun", "run", str(replay_script)],
                input=json.dumps(batch),
                text=True,
                check=True,
                capture_output=True,
                timeout=600,
            )
            return json.loads(completed.stdout)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            replay_rows = [row for batch in executor.map(replay_batch, batches) for row in batch]
    policy = pl.DataFrame(replay_rows, schema={
        "command": pl.String,
        "policyDecision": pl.String,
        "policyAllowed": pl.Boolean,
        "policyDenied": pl.Boolean,
        "reason": pl.String,
    }, strict=False).rename({
        "command": "replayed_command",
        "policyDecision": "policy_decision",
        "policyAllowed": "policy_allowed",
        "policyDenied": "policy_denied",
    }) if replay_rows else pl.DataFrame(schema={
        "replayed_command": pl.String,
        "policy_decision": pl.String,
        "policy_allowed": pl.Boolean,
        "policy_denied": pl.Boolean,
        "reason": pl.String,
    })
    return (policy,)


@app.cell
def _(history, pl, policy):
    results = history.with_row_index("replay_index").join(
        policy.with_row_index("replay_index"), on="replay_index", how="left"
    ).with_columns(
        (pl.col("policy_decision") == pl.col("historical_decision")).alias("decision_matches_history")
    )
    results
    return (results,)


@app.cell
def _(results):
    results.group_by(["historical_decision", "policy_decision", "decision_matches_history"]).len().sort("len", descending=True)
    return


if __name__ == "__main__":
    app.run()
