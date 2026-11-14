# Development notes

Run commands from the repository root after installing `requirements.txt`.

## Offline checks

Check Python syntax without importing the agent modules or contacting a model:

```bash
python3 -m compileall -q common path_explore path_verify ui main.py
```

Validate the bundled candidate's JSON format and source locations without making LLM requests:

```bash
python3 - <<'PY'
from pathlib import Path
from path_verify.utils import load_potential_paths

target = Path("examples/sast_paths")
paths = load_potential_paths(str(target / "potential_paths.json"))
assert paths
for path in paths:
    assert path.path
    for node in path.path:
        source = node.get_source_code(str(target))
        assert node.function_name + "(" in source
    assert path.sink_expression in path.path[-1].get_source_code(str(target))
print("Candidate JSON and source locations are valid.")
PY
```

This checks the input contract, not vulnerability-detection accuracy. Running the full verifier uses the configured LLM.

## Configuration lifecycle

- `common.config.get_config_path()` selects the configuration file. The default is the repository's `config.yaml`, anchored to the module location. The optional environment override is named by `common.config.CONFIG_ENV_VAR`; a relative override is resolved from the working directory.
- `load_config()` reads the file on first access and reuses the parsed dictionary. Missing required keys terminate the process; missing or blank optional decision-model fields allow fallback to the primary model.
- Default agent model settings are read during module import. Restart the process after editing configuration; changing the file in a running process does not refresh those defaults.
- The optional decision-model configuration is used only when its model, base URL, and API key are all populated. Otherwise, the final decision uses the primary model as well.
- Keep real API credentials and private endpoints out of commits. Stage only intended files; do not include local configuration changes in documentation or maintenance commits.

## Cache and retry behavior

Agent-response JSON files are stored in `cache/` relative to the working directory. The cache key includes the absolute target directory, system and user prompts, sorted allowed tools, and active model. It does not independently hash the target checkout's file contents. When changing target source code, review whether cached results should be invalidated before starting a fresh analysis. The `get_cache_stats()` and `clear_cache()` helpers in `common.base_claude_agent` inspect and remove response-cache files; clearing them forces subsequent analyses to call the model again.

`base_claude_agent()` makes one initial attempt and up to `agent.max_retries` additional attempts, each bounded by `agent.timeout_seconds`. Only the first attempt may reuse cached output. Missing or too-short output, structural validation failures, timeouts, and execution errors can trigger retries. A newly obtained result is written to the response cache only after it passes validation. Exhausted attempts return an unsuccessful `AgentResult`; analysis stages handle that failure rather than treating it as a successful exploitability verdict.

## Changes intended to preserve behavior

Keep agent prompts, parsing markers, model routing, retry settings, and serialized field names unchanged in documentation-only maintenance. Review the Python AST with docstrings removed to distinguish documentation edits from executable changes. Check input examples against `path_verify.models` and the same source checkout, and keep the English and Chinese README examples synchronized.

Do not commit generated results, logs, cache files, or credentials. The offline checks above do not require access to a target service or a model API.
