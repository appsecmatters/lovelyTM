// test_all_risk_scores.js
// Generates every possible combination of (technical difficulty, logistics difficulty,
// business impact) and computes the resulting business risk using the DifficultyMatrix
// and BusinessRiskMatrix defined in the specs.
//
// Run with:  node test_all_risk_scores.js

'use strict';

// ── Enums ──────────────────────────────────────────────────────────────────────

const SEVERITY   = ['Low', 'Medium', 'High'];
const DIFFICULTY = ['Low', 'Low-Medium', 'Medium', 'Medium-High', 'High'];

// ── Matrices ───────────────────────────────────────────────────────────────────

/**
 * DIFFICULTY_MATRIX[techIdx][logsIdx] → combined difficulty
 *
 * Rows: Technical Difficulty (Low … High)
 * Cols: Logistics Difficulty (Low … High)
 */
const DIFFICULTY_MATRIX = [
  // Log→  Low           Low-Medium     Medium         Medium-High    High
  /* Low */        ['Low',        'Low-Medium',  'Medium',      'Medium-High', 'High'],
  /* Low-Medium */ ['Low-Medium', 'Low-Medium',  'Medium',      'Medium-High', 'High'],
  /* Medium */     ['Medium',     'Medium',      'Medium-High', 'Medium-High', 'High'],
  /* Medium-High */['Medium-High','Medium-High', 'Medium-High', 'High',        'High'],
  /* High */       ['High',       'High',        'High',        'High',        'High'],
];

/**
 * BUSINESS_RISK_MATRIX[impactIdx][diffIdx] → business risk
 *
 * Rows: Business Impact  (Low … High)
 * Cols: Attack Difficulty (Low … High)
 */
const BUSINESS_RISK_MATRIX = [
  // Diff→  Low        Low-Med    Medium     Med-High   High
  /* Low */    ['Low',     'Low',     'Low',     'Low',     'Low'    ],
  /* Medium */ ['Medium',  'Medium',  'Medium',  'Low',     'Low'    ],
  /* High */   ['Critical','Critical','High',    'Medium',  'Medium' ],
];

// ── Scoring functions ──────────────────────────────────────────────────────────

function combineDifficulty(tech, logistics) {
  const tIdx = DIFFICULTY.indexOf(tech);
  const lIdx = DIFFICULTY.indexOf(logistics);
  if (tIdx < 0 || lIdx < 0) throw new Error(`Unknown difficulty: tech=${tech}, logistics=${logistics}`);
  return DIFFICULTY_MATRIX[tIdx][lIdx];
}

function computeBusinessRisk(businessImpact, techDiff, logsDiff) {
  const combined = combineDifficulty(techDiff, logsDiff);
  const iIdx     = SEVERITY.indexOf(businessImpact);
  const dIdx     = DIFFICULTY.indexOf(combined);
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

// Compute column widths
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
  const prevTech = idx > 0 ? results[idx - 1].techDiff : null;
  const prevLogs = idx > 0 ? results[idx - 1].logsDiff : null;

  // Visual separator between logistics groups
  if (idx > 0 && r.logsDiff !== prevLogs) {
    if (r.techDiff !== prevTech) console.log(separator);
  }

  console.log(padRow(COLUMNS.map(c => r[c.key])));
});

console.log(separator);
console.log(`\nTotal combinations: ${results.length}`);
console.log(`  ${DIFFICULTY.length} tech × ${DIFFICULTY.length} logistics × ${SEVERITY.length} impact = ${DIFFICULTY.length ** 2 * SEVERITY.length}`);

// ── Spot-check assertions ──────────────────────────────────────────────────────

let failures = 0;

function assert(techDiff, logsDiff, impact, expectedRisk) {
  const actual = computeBusinessRisk(impact, techDiff, logsDiff);
  if (actual !== expectedRisk) {
    console.error(`FAIL  tech=${techDiff}, logs=${logsDiff}, impact=${impact} → expected ${expectedRisk}, got ${actual}`);
    failures++;
  }
}

// Boundary cases from the spec matrices
assert('Low',  'Low',  'Low',    'Low');
assert('Low',  'Low',  'Medium', 'Medium');
assert('Low',  'Low',  'High',   'Critical');
assert('High', 'High', 'Low',    'Low');
assert('High', 'High', 'Medium', 'Low');
assert('High', 'High', 'High',   'Medium');
assert('Low',   'High',   'High', 'Medium');  // combined=High     → BusinessRisk[High][High] = Medium
assert('Medium','Medium', 'High', 'Medium');  // combined=Medium-High → BusinessRisk[High][Medium-High] = Medium
assert('Low',  'Low',  'High',   'Critical'); // combined=Low → Critical

// Verify DifficultyMatrix spot checks
function assertDiff(tech, logs, expected) {
  const actual = combineDifficulty(tech, logs);
  if (actual !== expected) {
    console.error(`FAIL  combineDifficulty(${tech}, ${logs}) → expected ${expected}, got ${actual}`);
    failures++;
  }
}

assertDiff('Low',         'Low',         'Low');
assertDiff('Low',         'Medium',      'Medium');
assertDiff('Medium',      'Medium',      'Medium-High');
assertDiff('Medium-High', 'High',        'High');
assertDiff('High',        'Low',         'High');
assertDiff('Low-Medium',  'Low',         'Low-Medium');
assertDiff('Low-Medium',  'Low-Medium',  'Low-Medium');
assertDiff('Medium',      'Low-Medium',  'Medium');

if (failures === 0) {
  console.log('\nAll spot-check assertions passed ✓');
} else {
  console.error(`\n${failures} assertion(s) FAILED`);
  process.exitCode = 1;
}
