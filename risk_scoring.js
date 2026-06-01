// risk_scoring.js — Pure scoring logic, no DOM/UI dependencies.
// Loaded as a plain <script> in the browser; also importable via require() in Node.

const SEVERITY   = ['None', 'Low', 'Medium', 'High'];
const DIFFICULTY = ['Low', 'Low-Medium', 'Medium', 'Medium-High', 'High'];

/**
 * DIFFICULTY_MATRIX[techIdx][logsIdx] = combined difficulty
 * Rows: Technical Difficulty (Low → High)
 * Cols: Logistics Difficulty (Low → High)
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
 * BUSINESS_RISK_MATRIX[impactIdx][diffIdx] = business risk
 * Rows: Business Impact (None → High)
 * Cols: Attack Difficulty (Low → High)
 */
const BUSINESS_RISK_MATRIX = [
  // Diff→ Low       Low-Med    Medium     Med-High   High
  /* None */   ['None',    'None',    'None',    'None',    'None'   ],
  /* Low */    ['Low',     'Low',     'Low',     'Low',     'Low'    ],
  /* Medium */ ['Medium',  'Medium',  'Medium',  'Low',     'Low'    ],
  /* High */   ['Critical','Critical','High',    'Medium',  'Medium' ],
];

const RISK_ORDER = ['NA', 'None', 'Low', 'Medium', 'High', 'Critical'];

function combineDifficulty(tech, logistics) {
  const tIdx = DIFFICULTY.indexOf(tech);
  const lIdx = DIFFICULTY.indexOf(logistics);
  if (tIdx < 0 || lIdx < 0) return null;
  return DIFFICULTY_MATRIX[tIdx][lIdx];
}

/**
 * Compute the BusinessRisk for one STRIDE letter of one interaction.
 * businessScenarios  – array of BusinessScenario for this letter
 * technicalScenarios – array of TechnicalScenario for this letter
 */
function computeRiskForLetter(businessScenarios, technicalScenarios) {
  if (!businessScenarios || businessScenarios.length === 0) return 'NA';

  let maxImpactIdx = -1;
  for (const s of businessScenarios) {
    const idx = SEVERITY.indexOf(s.businessImpact);
    if (idx > maxImpactIdx) maxImpactIdx = idx;
  }
  if (maxImpactIdx < 0) return 'NA';

  if (!technicalScenarios || technicalScenarios.length === 0) return 'NA';

  let minDiffIdx = DIFFICULTY.length;
  for (const t of technicalScenarios) {
    const combined = combineDifficulty(t.technicalDifficulty, t.logisticsDifficulty);
    if (combined !== null) {
      const idx = DIFFICULTY.indexOf(combined);
      if (idx < minDiffIdx) minDiffIdx = idx;
    }
  }
  if (minDiffIdx >= DIFFICULTY.length) return 'NA';

  return BUSINESS_RISK_MATRIX[maxImpactIdx][minDiffIdx];
}

function computeAllRisks(interaction) {
  const risks = {};
  for (const letter of ['s', 't', 'r', 'i', 'd', 'e']) {
    risks[letter] = computeRiskForLetter(
      interaction.businessImpact[letter],
      interaction.attackDifficulty[letter]
    );
  }
  return risks;
}

if (typeof module !== 'undefined') {
  module.exports = {
    SEVERITY, DIFFICULTY, DIFFICULTY_MATRIX, BUSINESS_RISK_MATRIX, RISK_ORDER,
    combineDifficulty, computeRiskForLetter, computeAllRisks,
  };
}
