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
  combineDifficulty,
  computeRiskForLetter,
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

// ── Result ─────────────────────────────────────────────────────────────────────

if (failures === 0) {
  console.log('\nAll assertions passed ✓');
} else {
  console.error(`\n${failures} assertion(s) FAILED`);
  process.exitCode = 1;
}
