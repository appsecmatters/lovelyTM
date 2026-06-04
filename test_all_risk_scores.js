// test_all_risk_scores.js
// Validates all possible (technical difficulty, logistics difficulty, business impact)
// combinations against the DifficultyMatrix and BusinessRiskMatrix in risk_scoring.js.
//
// Run with:  node test_all_risk_scores.js

'use strict';

const {
  SEVERITY,
  DIFFICULTY,
  ATTACK_DIFFICULTY,
  DIFFICULTY_MATRIX,
  BUSINESS_RISK_MATRIX,
  RISK_ORDER,
  EFFORT_SCORE,
  combineDifficulty,
  computeAttackDifficultyForScenario,
  computeRiskForLetter,
  computeRequirementScores,
} = require('./risk_scoring');

// ── Thin helper: raw values → business risk ────────────────────────────────────

function computeBusinessRisk(businessImpact, techDiff, logsDiff) {
  const combined = combineDifficulty(techDiff, logsDiff);
  if (combined === null) throw new Error(`Unknown difficulty: tech=${techDiff}, logs=${logsDiff}`);
  const iIdx = SEVERITY.indexOf(businessImpact);
  const dIdx = ATTACK_DIFFICULTY.indexOf(combined);
  if (iIdx < 0) throw new Error(`Unknown businessImpact: ${businessImpact}`);
  return BUSINESS_RISK_MATRIX[iIdx][dIdx];
}

// ── Generate all combinations ──────────────────────────────────────────────────

const results = [];

for (const techDiff of DIFFICULTY) {
  for (const logsDiff of DIFFICULTY) {
    for (const impact of SEVERITY) {
      const combined = combineDifficulty(techDiff, logsDiff);
      const risk     = computeBusinessRisk(impact, techDiff, logsDiff);
      results.push({ techDiff, logsDiff, impact, combined, risk });
    }
  }
}

// ── Pretty-print as a table ────────────────────────────────────────────────────

const COLUMNS = [
  { key: 'techDiff', label: 'Tech Difficulty'     },
  { key: 'logsDiff', label: 'Logistics Difficulty' },
  { key: 'impact',   label: 'Business Impact'      },
  { key: 'combined', label: 'Combined Difficulty'  },
  { key: 'risk',     label: 'Business Risk'        },
];

const widths = COLUMNS.map(col =>
  Math.max(col.label.length, ...results.map(r => r[col.key].length))
);

function padRow(cells) {
  return '| ' + cells.map((c, i) => c.padEnd(widths[i])).join(' | ') + ' |';
}

const separator = '+' + widths.map(w => '-'.repeat(w + 2)).join('+') + '+';

console.log(separator);
console.log(padRow(COLUMNS.map(c => c.label)));
console.log(separator);

results.forEach((r, idx) => {
  const prevLogs = idx > 0 ? results[idx - 1].logsDiff : null;
  const prevTech = idx > 0 ? results[idx - 1].techDiff : null;
  if (idx > 0 && r.logsDiff !== prevLogs && r.techDiff !== prevTech) console.log(separator);
  console.log(padRow(COLUMNS.map(c => r[c.key])));
});

console.log(separator);
console.log(`\nTotal combinations: ${results.length}`);
console.log(`  ${DIFFICULTY.length} tech × ${DIFFICULTY.length} logistics × ${SEVERITY.length} impact = ${DIFFICULTY.length ** 2 * SEVERITY.length}`);

// ── Assertions ─────────────────────────────────────────────────────────────────

let failures = 0;

function assert(techDiff, logsDiff, impact, expectedRisk, note) {
  const actual = computeBusinessRisk(impact, techDiff, logsDiff);
  if (actual !== expectedRisk) {
    const label = note ? ` (${note})` : '';
    console.error(`FAIL  tech=${techDiff}, logs=${logsDiff}, impact=${impact} → expected ${expectedRisk}, got ${actual}${label}`);
    failures++;
  }
}

function assertDiff(tech, logs, expected) {
  const actual = combineDifficulty(tech, logs);
  if (actual !== expected) {
    console.error(`FAIL  combineDifficulty(${tech}, ${logs}) → expected ${expected}, got ${actual}`);
    failures++;
  }
}

// ── Property checks (enforced over all difficulty combinations) ────────────────

// Spec: "None business impact always returns None"
for (const techDiff of DIFFICULTY) {
  for (const logsDiff of DIFFICULTY) {
    assert(techDiff, logsDiff, 'None', 'None', 'None impact → always None');
  }
}

// Spec: "Low business impact always returns Low"
for (const techDiff of DIFFICULTY) {
  for (const logsDiff of DIFFICULTY) {
    assert(techDiff, logsDiff, 'Low', 'Low', 'Low impact → always Low');
  }
}

// Spec: "Medium business impact always returns Low, Medium or NA"
const mediumIdx = RISK_ORDER.indexOf('Medium');
for (const techDiff of DIFFICULTY) {
  for (const logsDiff of DIFFICULTY) {
    const risk = computeBusinessRisk('Medium', techDiff, logsDiff);
    if (risk !== 'Low' && risk !== 'Medium' && risk !== 'NA') {
      console.error(`FAIL  tech=${techDiff}, logs=${logsDiff}, impact=Medium → ${risk} is not Low, Medium or NA`);
      failures++;
    }
  }
}

// Spec: "High business impact returns at least Medium or NA"
for (const techDiff of DIFFICULTY) {
  for (const logsDiff of DIFFICULTY) {
    const risk = computeBusinessRisk('High', techDiff, logsDiff);
    if (risk !== 'NA' && RISK_ORDER.indexOf(risk) < mediumIdx) {
      console.error(`FAIL  tech=${techDiff}, logs=${logsDiff}, impact=High → ${risk} is below Medium`);
      failures++;
    }
  }
}

// ── NA attack difficulty (empty technicalScenarios) ────────────────────────────

console.log('\nNA attack difficulty (no TechnicalScenarios):');

function assertNADiff(impact, expectedRisk) {
  const biz = [{ businessImpact: impact }];
  const actual = computeRiskForLetter(biz, []);
  const ok = actual === expectedRisk;
  console.log(`  impact=${impact.padEnd(6)} → ${actual}${ok ? '' : ` (expected ${expectedRisk})`}`);
  if (!ok) failures++;
}

assertNADiff('None',   'None');
assertNADiff('Low',    'Low');
assertNADiff('Medium', 'NA');
assertNADiff('High',   'NA');

// ── Spot checks: BusinessRiskMatrix corners ────────────────────────────────────

assert('Low',  'Low',  'None',   'None');
assert('Low',  'Low',  'Low',    'Low');
assert('Low',  'Low',  'Medium', 'Medium');
assert('Low',  'Low',  'High',   'Critical');
assert('High', 'High', 'None',   'None');
assert('High', 'High', 'Low',    'Low');
assert('High', 'High', 'Medium', 'Low');
assert('High', 'High', 'High',   'Medium');
assert('Low',  'High', 'High',   'Medium');      // combined=High → Critical/High/Medium row → Medium
assert('Medium','Medium','High', 'Medium');      // combined=Medium-High → Medium

// ── Spot checks: DifficultyMatrix ─────────────────────────────────────────────

assertDiff('Low',         'Low',         'Low');
assertDiff('Low',         'Medium',      'Medium');
assertDiff('Medium',      'Medium',      'Medium-High');
assertDiff('Medium-High', 'High',        'High');
assertDiff('High',        'Low',         'High');
assertDiff('Low-Medium',  'Low',         'Low-Medium');
assertDiff('Low-Medium',  'Low-Medium',  'Low-Medium');
assertDiff('Medium',      'Low-Medium',  'Medium');

// ── RequirementInstances: computeAttackDifficultyForScenario ─────────────────

console.log('\ncomputeAttackDifficultyForScenario:');

function assertScenarioDiff(scenario, expected, note) {
  const actual = computeAttackDifficultyForScenario(scenario);
  const ok = actual === expected;
  console.log(`  ${note}: → ${actual}${ok ? '' : ` (expected ${expected})`}`);
  if (!ok) failures++;
}

function mkScenario(tech, logs, reqs) {
  return { technicalDifficulty: tech, logisticsDifficulty: logs, requirementInstances: reqs };
}

function mkReq(updatedTech, updatedLogs) {
  return { updatedTechDifficulty: updatedTech, updatedLogisticsDifficulty: updatedLogs };
}

// No requirements → default difficulty
assertScenarioDiff(mkScenario('Low',    'Low',    []), 'Low',         'no reqs, Low+Low');
assertScenarioDiff(mkScenario('Medium', 'Medium', []), 'Medium-High', 'no reqs, Medium+Medium');
assertScenarioDiff(mkScenario('High',   'High',   []), 'High',        'no reqs, High+High');

// One requirement overrides
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('Medium', 'Low')]),
  'Medium',  // DIFFICULTY_MATRIX[Medium][Low] = Medium
  '1 req: maxTech=Medium, maxLogs=Low → Medium'
);
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('High', 'High')]),
  'High',    // DIFFICULTY_MATRIX[High][High] = High
  '1 req: maxTech=High, maxLogs=High → High'
);

// Multiple requirements: max per dimension independently
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('Medium', 'Low'), mkReq('Low', 'High')]),
  'High',    // maxTech=Medium, maxLogs=High → DIFFICULTY_MATRIX[Medium][High] = High
  '2 reqs: maxTech=Medium maxLogs=High → High'
);
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('Medium-High', 'Medium'), mkReq('Medium', 'Medium-High')]),
  'High',    // maxTech=Medium-High, maxLogs=Medium-High → DIFFICULTY_MATRIX[Medium-High][Medium-High] = High
  '2 reqs: maxTech=Medium-High maxLogs=Medium-High → High'
);

// All-NA requirements → fall back to default (spec: if either max dim is NA, use default)
assertScenarioDiff(
  mkScenario('High', 'High', [mkReq('NA', 'NA')]),
  'High',    // maxTech=NA or maxLogs=NA → fallback to default High+High = High
  'all-NA req → fallback default High+High'
);
assertScenarioDiff(
  mkScenario('Low', 'Medium', [mkReq('NA', 'NA')]),
  'Medium',  // maxTech=NA → fallback: DIFFICULTY_MATRIX[Low][Medium] = Medium
  'all-NA req → fallback default Low+Medium'
);

// Partial NA: one dimension is NA across all reqs → still falls back
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('High', 'NA')]),
  'Low',     // maxTech=High, maxLogs=NA → maxLogs is NA → fallback Low+Low = Low
  '1 req NA logs → fallback default Low+Low'
);
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('NA', 'High')]),
  'Low',     // maxTech=NA → fallback Low+Low = Low
  '1 req NA tech → fallback default Low+Low'
);
// Mix: one req has partial NA, another covers both dims → max wins, no fallback
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('High', 'NA'), mkReq('NA', 'High')]),
  'High',    // maxTech=High (from req1), maxLogs=High (from req2) → both non-NA → High+High = High
  '2 reqs cross-covering both dims → High+High'
);

// Mix of NA and non-NA: max picks non-NA values
assertScenarioDiff(
  mkScenario('Low', 'Low', [mkReq('NA', 'NA'), mkReq('Medium-High', 'Medium')]),
  'Medium-High',  // maxTech=Medium-High, maxLogs=Medium → DIFFICULTY_MATRIX[Medium-High][Medium] = Medium-High
  'NA + Medium-High/Medium → Medium-High'
);

// Requirements cannot lower attack difficulty below the scenario default
assertScenarioDiff(
  mkScenario('High', 'High', [mkReq('Low', 'Low')]),
  'High',         // updated Low+Low=Low < default High+High=High → clamped to High
  'req below default (Low<High) → clamped to default High'
);
assertScenarioDiff(
  mkScenario('Medium', 'Medium', [mkReq('Low', 'Low')]),
  'Medium-High',  // updated Low+Low=Low < default Medium+Medium=Medium-High → clamped
  'req below default (Low<Medium-High) → clamped to default Medium-High'
);

// ── Integration: computeRiskForLetter with RequirementInstances ───────────────

console.log('\ncomputeRiskForLetter with RequirementInstances:');

function assertRiskWithReqs(biz, techScenarios, expected, note) {
  const actual = computeRiskForLetter(biz, techScenarios);
  const ok = actual === expected;
  console.log(`  ${note}: → ${actual}${ok ? '' : ` (expected ${expected})`}`);
  if (!ok) failures++;
}

// No requirements: unchanged baseline
assertRiskWithReqs(
  [{ businessImpact: 'High' }],
  [mkScenario('Low', 'Low', [])],
  'Critical',  // default Low → BUSINESS_RISK_MATRIX[High][Low] = Critical
  'High impact, Low+Low, no reqs → Critical'
);

// Requirements raise difficulty → lower risk
assertRiskWithReqs(
  [{ businessImpact: 'High' }],
  [mkScenario('Low', 'Low', [mkReq('High', 'High')])],
  'Medium',    // updated High → BUSINESS_RISK_MATRIX[High][High] = Medium
  'High impact, Low+Low, req→High+High → Medium'
);
assertRiskWithReqs(
  [{ businessImpact: 'Medium' }],
  [mkScenario('Low', 'Low', [mkReq('Medium-High', 'Medium')])],
  'Low',       // updated Medium-High → BUSINESS_RISK_MATRIX[Medium][Medium-High] = Low
  'Medium impact, req→Medium-High/Medium → Low'
);

// Multiple scenarios: min across scenarios (easiest attack path wins)
assertRiskWithReqs(
  [{ businessImpact: 'High' }],
  [
    mkScenario('Low', 'Low', [mkReq('High', 'High')]),  // updated → High
    mkScenario('Low', 'Low', []),                        // default → Low (easier)
  ],
  'Critical',  // min difficulty = Low → Critical
  'High impact, 2 scenarios: one mitigated (High), one bare (Low) → Critical'
);

// All-NA requirements: baseline preserved
assertRiskWithReqs(
  [{ businessImpact: 'High' }],
  [mkScenario('Low', 'Low', [mkReq('NA', 'NA')])],
  'Critical',  // fallback to Low → Critical
  'High impact, all-NA req → fallback Low → Critical'
);

// ── computeRequirementScores ──────────────────────────────────────────────────

console.log('\ncomputeRequirementScores:');

// Assert helper: checks score (and optionally efficiency within 0.001)
function assertReqScore(label, secReq, ias, expectedScore, expectedEff) {
  const { score, efficiency } = computeRequirementScores(secReq, ias);
  const scoreOk = score === expectedScore;
  const effOk   = expectedEff === undefined || Math.abs(efficiency - expectedEff) < 0.001;
  if (!scoreOk || !effOk) {
    const effNote = expectedEff !== undefined ? ` eff=${expectedEff.toFixed(3)}` : '';
    console.error(`FAIL  ${label}: expected score=${expectedScore}${effNote}, got score=${score} eff=${efficiency.toFixed(3)}`);
    failures++;
  } else {
    console.log(`  ${label}: score=${score} eff=${efficiency.toFixed(2)} ✓`);
  }
}

// Build one interaction with a single TechScenario + RequirementInstance in STRIDE letter 's'
function mkReqInteraction(src, dst, bizImpact, tsDiff, reqDiff, secReq) {
  const ri = {
    secRequirement:             secReq,
    updatedTechDifficulty:      reqDiff[0],
    updatedLogisticsDifficulty: reqDiff[1],
  };
  const ts = { technicalDifficulty: tsDiff[0], logisticsDifficulty: tsDiff[1], requirementInstances: [ri] };
  const biz = bizImpact ? [{ businessImpact: bizImpact }] : [];
  return {
    source: src, destination: dst,
    businessImpact:   { s: biz, t: [], r: [], i: [], d: [], e: [] },
    attackDifficulty: { s: [ts], t: [], r: [], i: [], d: [], e: [] },
  };
}

function mkSecReq(title, effort, src, dst) {
  return { title, description: '', source: src, destination: dst, effort, status: 'NA' };
}

// ── Baseline: no contribution cases ───────────────────────────────────────────

const srBase = mkSecReq('base', 'Low', 'A', 'B');

// NA placeholder → 0 (updatedTech/Logs not yet filled in)
assertReqScore(
  'NA placeholder → score 0',
  srBase,
  [mkReqInteraction('A', 'B', 'High', ['Low', 'Low'], ['NA', 'NA'], srBase)],
  0
);

// No business scenarios → skip (maxImpactIdx = -1)
assertReqScore(
  'no business scenarios → score 0',
  srBase,
  [mkReqInteraction('A', 'B', null, ['Low', 'Low'], ['Medium-High', 'Low'], srBase)],
  0
);

// Same updated difficulty as default → same risk → 0
assertReqScore(
  'same difficulty → score 0',
  srBase,
  [mkReqInteraction('A', 'B', 'High', ['Low', 'Low'], ['Low', 'Low'], srBase)],
  0
);

// Updated difficulty below default → clamped to default → same risk → 0
assertReqScore(
  'req below default (Low<High+High) → clamped → score 0',
  srBase,
  [mkReqInteraction('A', 'B', 'High', ['High', 'High'], ['Low', 'Low'], srBase)],
  0
);

// ── Spot-check each reachable BUSINESS_RISK_SCORE_TABLE entry ─────────────────

// TABLE[1][3] = 4 : updated=Medium, default=Critical
//   High impact + default Low+Low=Low → Critical; updated Medium-High+Low=Medium-High → Medium
{
  const sr = mkSecReq('T[1][3]', 'Low', 'A', 'B');
  assertReqScore(
    'TABLE[Medium][Critical]=4',
    sr,
    [mkReqInteraction('A', 'B', 'High', ['Low', 'Low'], ['Medium-High', 'Low'], sr)],
    4,
    4 / EFFORT_SCORE['Low']   // 4/3
  );
}

// TABLE[2][3] = 2 : updated=High, default=Critical
//   High impact + default Low+Low=Low → Critical; updated Medium+Low=Medium → High
{
  const sr = mkSecReq('T[2][3]', 'Medium', 'A', 'B');
  assertReqScore(
    'TABLE[High][Critical]=2',
    sr,
    [mkReqInteraction('A', 'B', 'High', ['Low', 'Low'], ['Medium', 'Low'], sr)],
    2,
    2 / EFFORT_SCORE['Medium']  // 2/10
  );
}

// TABLE[0][1] = 1 : updated=Low, default=Medium
//   Medium impact + default Low+Low=Low → Medium; updated Medium-High+Low=Medium-High → Low
{
  const sr = mkSecReq('T[0][1]', 'VeryLow', 'A', 'B');
  assertReqScore(
    'TABLE[Low][Medium]=1',
    sr,
    [mkReqInteraction('A', 'B', 'Medium', ['Low', 'Low'], ['Medium-High', 'Low'], sr)],
    1,
    1 / EFFORT_SCORE['VeryLow']  // 1/1
  );
}

// TABLE[1][2] = 2 : updated=Medium, default=High
//   High impact + default Medium+Low=Medium → High; updated Medium-High+Low=Medium-High → Medium
{
  const sr = mkSecReq('T[1][2]', 'High', 'A', 'B');
  assertReqScore(
    'TABLE[Medium][High]=2',
    sr,
    [mkReqInteraction('A', 'B', 'High', ['Medium', 'Low'], ['Medium-High', 'Low'], sr)],
    2,
    2 / EFFORT_SCORE['High']  // 2/30
  );
}

// ── Key invariant: two requirements on the same TechScenario → different scores ─

console.log('\n  Different requirements must not always return the same score:');
{
  const srStrong = mkSecReq('strong', 'Low', 'A', 'B');
  const srWeak   = mkSecReq('weak',   'Low', 'A', 'B');
  const ts = {
    technicalDifficulty: 'Low', logisticsDifficulty: 'Low',
    requirementInstances: [
      { secRequirement: srStrong, updatedTechDifficulty: 'Medium-High', updatedLogisticsDifficulty: 'Low' },
      { secRequirement: srWeak,   updatedTechDifficulty: 'Low',          updatedLogisticsDifficulty: 'Low' },
    ],
  };
  const ia = {
    source: 'A', destination: 'B',
    businessImpact:   { s: [{ businessImpact: 'High' }], t: [], r: [], i: [], d: [], e: [] },
    attackDifficulty: { s: [ts], t: [], r: [], i: [], d: [], e: [] },
  };
  assertReqScore('2 reqs same TS — strong (expect 4)', srStrong, [ia], 4);
  assertReqScore('2 reqs same TS — weak   (expect 0)', srWeak,   [ia], 0);
  const sStrong = computeRequirementScores(srStrong, [ia]).score;
  const sWeak   = computeRequirementScores(srWeak,   [ia]).score;
  if (sStrong !== sWeak) {
    console.log('  Confirmed: different requirements produce different scores (' + sStrong + ' ≠ ' + sWeak + ') ✓');
  } else {
    console.error('FAIL  different requirements returned the same score (' + sStrong + ')');
    failures++;
  }
}

// ── Actor-pair filtering ───────────────────────────────────────────────────────

{
  const srAB = mkSecReq('AB', 'Low', 'A', 'B');
  const srAC = mkSecReq('AC', 'Low', 'A', 'C');
  const iaAB = mkReqInteraction('A', 'B', 'High', ['Low', 'Low'], ['Medium-High', 'Low'], srAB);
  const iaAC = mkReqInteraction('A', 'C', 'High', ['Low', 'Low'], ['Medium-High', 'Low'], srAC);

  // Each req scores 4 against its own interaction and 0 against the other
  assertReqScore('A→B req vs [A→B, A→C] interactions', srAB, [iaAB, iaAC], 4);
  assertReqScore('A→C req vs [A→B, A→C] interactions', srAC, [iaAB, iaAC], 4);
  assertReqScore('A→B req vs A→C-only interactions (expect 0)', srAB, [iaAC], 0);
}

// ── Multiple TechScenarios accumulate ─────────────────────────────────────────

{
  const sr = mkSecReq('multi', 'Low', 'A', 'B');
  const riS = { secRequirement: sr, updatedTechDifficulty: 'Medium-High', updatedLogisticsDifficulty: 'Low' };
  const riT = { secRequirement: sr, updatedTechDifficulty: 'Medium-High', updatedLogisticsDifficulty: 'Low' };
  const tsS = { technicalDifficulty: 'Low', logisticsDifficulty: 'Low', requirementInstances: [riS] };
  const tsT = { technicalDifficulty: 'Low', logisticsDifficulty: 'Low', requirementInstances: [riT] };
  const ia = {
    source: 'A', destination: 'B',
    businessImpact:   { s: [{ businessImpact: 'High' }], t: [{ businessImpact: 'High' }], r: [], i: [], d: [], e: [] },
    attackDifficulty: { s: [tsS], t: [tsT], r: [], i: [], d: [], e: [] },
  };
  // Each scenario contributes TABLE[1][3]=4 → total = 8
  assertReqScore('2 TechScenarios across 2 STRIDE letters (expect 8)', sr, [ia], 8);
}

// ── Result ─────────────────────────────────────────────────────────────────────

if (failures === 0) {
  console.log('\nAll assertions passed ✓');
} else {
  console.error(`\n${failures} assertion(s) FAILED`);
  process.exitCode = 1;
}
