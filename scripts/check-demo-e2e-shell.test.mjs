import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const scriptURL = new URL('./check-demo-e2e.sh', import.meta.url);
const source = readFileSync(scriptURL, 'utf8');

test('Compose E2E shell grants one signed-history target and separates lifecycle modes', () => {
  assert.match(source, /e2e_mode="release_expiry"/);
  assert.match(source, /e2e_mode="fast_revoke"/);
  assert.match(source, /node "\$helper" approve \\\n(?:.*\n){0,8}\s+--mode "\$e2e_mode"/);
  assert.match(source, /read -r persisted_mode action_target_ipv4 approved_ttl/);
  assert.match(source, /"\$action_target_ipv4" != "203\.0\.113\.20"/);
  assert.match(source, /run_bounded 420 node "\$helper" verify-inspected/);
  assert.match(source, /--timeout-seconds 300/);

  const occurrences = [...source.matchAll(/203\.0\.113\.24/g)];
  assert.equal(occurrences.length, 1);
  assert.match(source, /run_scenario brute-force 203\.0\.113\.24/);
  for (const stale of [
    'expiry_target_ipv4', 'revoke_target_ipv4', 'expiry_action', 'revoke_action',
    'expiry_add', 'revoke_add', 'two independent exact HIL artifacts',
  ]) {
    assert.equal(source.includes(stale), false, `stale two-action token remains: ${stale}`);
  }
});

test('revoke commands are confined to fast mode and release owns native expiry', () => {
  const fastStart = source.indexOf(
    'if [[ "$e2e_mode" == "fast_revoke" ]]; then\n  printf \'==> Proving a digest-mismatched revoke',
  );
  const releaseStart = source.indexOf('\nelse\n  if ! validate_persisted_evidence', fastStart);
  const commonOutage = source.indexOf("\nfi\n\nprintf '==> Proving control-plane outage", releaseStart);
  assert.ok(fastStart > 0 && releaseStart > fastStart && commonOutage > releaseStart);

  const fastOnly = source.slice(fastStart, releaseStart);
  const releaseOnly = source.slice(releaseStart, commonOutage);
  const negativeRevoke = /node "\$helper" prove-revoke-negative/g;
  const exactRevoke = /node "\$helper" revoke \\/g;
  assert.equal((fastOnly.match(negativeRevoke) ?? []).length, 1);
  assert.equal((fastOnly.match(exactRevoke) ?? []).length, 1);
  assert.doesNotMatch(releaseOnly, /node "\$helper" (?:prove-revoke-negative|revoke)/);
  assert.equal((source.match(negativeRevoke) ?? []).length, 1);
  assert.equal((source.match(exactRevoke) ?? []).length, 1);

  const expiryInvocation = source.indexOf('node "$helper" verify-expired');
  const terminalElse = source.lastIndexOf('\nelse\n', expiryInvocation);
  assert.ok(expiryInvocation > commonOutage && terminalElse > commonOutage);
  assert.doesNotMatch(source.slice(fastStart, commonOutage), /verify-expired/);
  const releaseTerminalEnd = source.indexOf(
    "\nfi\n\nprintf '==> Removing only the exact Compose project",
    terminalElse,
  );
  assert.ok(releaseTerminalEnd > terminalElse);
  const releaseTerminal = source.slice(terminalElse, releaseTerminalEnd);
  assert.equal((releaseTerminal.match(/node "\$helper" verify-expired/g) ?? []).length, 1);
  assert.equal((releaseTerminal.match(/"\$validation_terminal_journal" "expired"; then/g) ?? []).length, 1);
  assert.equal((source.match(/"\$validation_terminal_journal" "expired"; then/g) ?? []).length, 1);
  assert.doesNotMatch(releaseTerminal, /node "\$helper" (?:prove-revoke-negative|revoke)/);
  assert.match(source, /hold_for_browser_qa active/);
  assert.match(fastOnly, /hold_for_browser_qa revoked/);
});

test('browser hold arguments fail before Docker and are bounded per phase', () => {
  const cases = [
    [['--browser-qa-hold-seconds'], 2, 'Usage:'],
    [['--browser-qa-hold-seconds', '59'], 2, 'integer from 60 through 900'],
    [['--browser-qa-hold-seconds', '901'], 2, 'integer from 60 through 900'],
    [['--fast', '--browser-qa-hold-seconds', '60', '--browser-qa-hold-seconds', '60'], 2, 'Usage:'],
  ];
  for (const [args, expectedStatus, expectedText] of cases) {
    const result = spawnSync(scriptURL.pathname, args, { encoding: 'utf8' });
    assert.equal(result.status, expectedStatus, args.join(' '));
    assert.match(`${result.stdout}${result.stderr}`, new RegExp(expectedText));
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /docker/i);
  }
});

test('fast E2E excludes host OpenAI credentials and selects only the deterministic stub', () => {
  assert.match(source,
    /unset OPENAI_API_KEY OPENAI_MODEL OPENAI_REASONING_EFFORT OPENAI_STORE/);

  const composeFunctionStart = source.indexOf('compose() {');
  const composeFunctionEnd = source.indexOf('\n}\n\nremove_exact_project()', composeFunctionStart);
  assert.ok(composeFunctionStart >= 0 && composeFunctionEnd > composeFunctionStart);
  const composeFunction = source.slice(composeFunctionStart, composeFunctionEnd);
  assert.match(composeFunction,
    /env COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose/);
  assert.match(composeFunction, /--profile stub-ai/);

  assert.match(source, /printf 'COMPOSE_PROFILES=stub-ai\\n'/);
  assert.match(source,
    /env COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \\\n/);
  assert.match(source,
    /node "\$helper" check-compose "\$compose_config_file"/);
});

test('failure diagnostics capture only bounded detector and validationworker runtime state', () => {
  assert.match(source,
    /detection_diagnostic_validationworker_file="\$temp_root\/detection-diagnostic-validationworker\.json"/);
  assert.match(source, /validationworker_id="\$\(compose 30 ps --quiet validationworker\)"/);
  assert.match(source, /test -n "\$validationworker_id"/);
  const captureStart = source.indexOf('capture_detection_diagnostics() {');
  const captureEnd = source.indexOf('\nwait_for_cold_start_coverage() {', captureStart);
  assert.ok(captureStart >= 0 && captureEnd > captureStart);
  const capture = source.slice(captureStart, captureEnd);
  const exactRuntimeFormat = /--format '\{"running":\{\{json \.State\.Running\}\},"restart_count":\{\{json \.RestartCount\}\}\}'/g;
  assert.equal((capture.match(exactRuntimeFormat) ?? []).length, 2);
  assert.match(capture, /"\$detector_id" >"\$detection_diagnostic_detector_file"/);
  assert.match(capture,
    /"\$validationworker_id" >"\$detection_diagnostic_validationworker_file"/);
  assert.match(capture,
    /--detector "\$detection_diagnostic_detector_file" \\\n\s+--validationworker "\$detection_diagnostic_validationworker_file" --stage "\$stage"/);
  assert.doesNotMatch(capture, /docker logs|\.Config\.Env|\.Id|container_id|inspect --format '\{\{'/);
});

test('evidence-chain SQL is parsed on migrated PostgreSQL before the long coverage wait', () => {
  assert.match(source,
    /evidence_sql_preflight_file="\$temp_root\/evidence-chain-preflight\.ndjson"/);
  const functionStart = source.indexOf('preflight_evidence_chain_sql() {');
  const functionEnd = source.indexOf('\n\ncapture_detection_diagnostics() {', functionStart);
  assert.ok(functionStart >= 0 && functionEnd > functionStart,
    'evidence-chain SQL preflight function is missing');
  const preflight = source.slice(functionStart, functionEnd);
  assert.match(preflight, /zero_job_id="00000000-0000-0000-0000-000000000000"/);
  assert.match(preflight,
    /postgres_query "\$evidence_sql_file" "\$evidence_sql_preflight_file" \\\n\s+--set="add_job=\$zero_job_id" --set="revoke_job="/);
  assert.match(preflight, /\[\[ -s "\$evidence_sql_preflight_file" \]\]/);
  assert.match(preflight, /rm -f "\$evidence_sql_preflight_file"/);

  const postgresReady = source.indexOf('postgres_id="$(compose 30 ps --quiet postgres)"');
  const invocation = source.indexOf('\npreflight_evidence_chain_sql\n', postgresReady);
  const coverageWait = source.indexOf('\nwait_for_cold_start_coverage\n', invocation);
  assert.ok(postgresReady >= 0 && invocation > postgresReady && coverageWait > invocation,
    'migrated PostgreSQL must parse the evidence SQL before the 305-second coverage wait');
});

test('control-plane recovery does not re-run one-shot migration services', () => {
  const outageStart = source.indexOf("printf '==> Proving control-plane outage");
  const restartStart = source.indexOf("printf '==> Restarting dispatcher", outageStart);
  const restartEnd = source.indexOf('\nexecutor_id=', restartStart);
  assert.ok(outageStart >= 0 && restartStart > outageStart && restartEnd > restartStart);
  const recovery = source.slice(outageStart, restartEnd);
  assert.match(recovery,
    /compose 360 up --no-deps --detach --wait --wait-timeout 240 --no-build \\\n\s+api detector validationworker lifecycleworker stubworker dispatcher/);
  assert.match(recovery,
    /compose 360 up --no-deps --detach --wait --wait-timeout 240 --no-build \\\n\s+dispatcher executor gateway/);
  assert.doesNotMatch(recovery, /compose 360 up --detach --wait --wait-timeout 240 --no-build\n/);
});
