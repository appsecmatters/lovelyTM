// risk_scoring.js — Pure scoring logic, no DOM/UI dependencies.
// Loaded as a plain <script> in the browser; also importable via require() in Node.

const SEVERITY = ['None', 'Low', 'Medium', 'High'];

// Used by DifficultyMatrix (user-selectable values only — NA is never combined).
const DIFFICULTY = ['Low', 'Low-Medium', 'Medium', 'Medium-High', 'High'];

// Used as the column index for BusinessRiskMatrix.
// NA represents the absence of any TechnicalScenario for this letter.
const ATTACK_DIFFICULTY = ['NA', 'Low', 'Low-Medium', 'Medium', 'Medium-High', 'High'];

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
 * BUSINESS_RISK_MATRIX[impactIdx][attackDiffIdx] = business risk
 * Rows: Business Impact  (None → High)
 * Cols: Attack Difficulty (NA → High)
 */
const BUSINESS_RISK_MATRIX = [
  // AttackDiff→ NA      Low        Low-Med    Medium     Med-High   High
  /* None */   ['None',  'None',    'None',    'None',    'None',    'None'   ],
  /* Low */    ['Low',   'Low',     'Low',     'Low',     'Low',     'Low'    ],
  /* Medium */ ['NA',    'Medium',  'Medium',  'Medium',  'Low',     'Low'    ],
  /* High */   ['NA',    'Critical','Critical','High',    'Medium',  'Medium' ],
];

const RISK_ORDER = ['NA', 'None', 'Low', 'Medium', 'High', 'Critical'];

function combineDifficulty(tech, logistics) {
  const tIdx = DIFFICULTY.indexOf(tech);
  const lIdx = DIFFICULTY.indexOf(logistics);
  if (tIdx < 0 || lIdx < 0) return null;
  return DIFFICULTY_MATRIX[tIdx][lIdx];
}

/**
 * Compute the effective attack difficulty for a single TechnicalScenario,
 * taking its RequirementInstances into account (spec v0.51 step 2).
 *
 * - No requirements → combineDifficulty(tech, logs) of the scenario itself.
 * - With requirements → find max(updatedTechDifficulty) and max(updatedLogisticsDifficulty)
 *   across all instances (using ATTACK_DIFFICULTY ordering so NA stays lowest),
 *   then combine through DifficultyMatrix. Falls back to the default when the
 *   combination is invalid (e.g. all-NA updates).
 */
function computeAttackDifficultyForScenario(scenario) {
  const defaultDiff = combineDifficulty(scenario.technicalDifficulty, scenario.logisticsDifficulty);

  const reqs = scenario.requirementInstances || [];
  if (reqs.length === 0) return defaultDiff;

  let maxTechIdx = -1;
  let maxLogsIdx = -1;
  for (const ri of reqs) {
    const tIdx = ATTACK_DIFFICULTY.indexOf(ri.updatedTechDifficulty);
    const lIdx = ATTACK_DIFFICULTY.indexOf(ri.updatedLogisticsDifficulty);
    if (tIdx > maxTechIdx) maxTechIdx = tIdx;
    if (lIdx > maxLogsIdx) maxLogsIdx = lIdx;
  }

  const maxTech = maxTechIdx >= 0 ? ATTACK_DIFFICULTY[maxTechIdx] : 'NA';
  const maxLogs = maxLogsIdx >= 0 ? ATTACK_DIFFICULTY[maxLogsIdx] : 'NA';

  // Spec: if either max dimension is NA (no requirement constrains it), fall back to default
  if (maxTech === 'NA' || maxLogs === 'NA') return defaultDiff;
  return combineDifficulty(maxTech, maxLogs);
}

/**
 * Compute the BusinessRisk for one STRIDE letter of one interaction.
 * businessScenarios  – array of BusinessScenario for this letter
 * technicalScenarios – array of TechnicalScenario for this letter
 *
 * When technicalScenarios is empty, attack difficulty is treated as NA.
 * The matrix then determines the result: None/Low still score, Medium/High return NA.
 */
function computeRiskForLetter(businessScenarios, technicalScenarios) {
  if (!businessScenarios || businessScenarios.length === 0) return 'NA';

  let maxImpactIdx = -1;
  for (const s of businessScenarios) {
    const idx = SEVERITY.indexOf(s.businessImpact);
    if (idx > maxImpactIdx) maxImpactIdx = idx;
  }
  if (maxImpactIdx < 0) return 'NA';

  let minAttackDifficulty;
  if (!technicalScenarios || technicalScenarios.length === 0) {
    minAttackDifficulty = 'NA';
  } else {
    let minDiffIdx = DIFFICULTY.length;
    for (const t of technicalScenarios) {
      const attackDiff = computeAttackDifficultyForScenario(t);
      if (attackDiff !== null) {
        const idx = DIFFICULTY.indexOf(attackDiff);
        if (idx >= 0 && idx < minDiffIdx) minDiffIdx = idx;
      }
    }
    minAttackDifficulty = minDiffIdx < DIFFICULTY.length ? DIFFICULTY[minDiffIdx] : 'NA';
  }

  const dIdx = ATTACK_DIFFICULTY.indexOf(minAttackDifficulty);
  if (dIdx < 0) return 'NA';
  return BUSINESS_RISK_MATRIX[maxImpactIdx][dIdx];
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
    SEVERITY, DIFFICULTY, ATTACK_DIFFICULTY, DIFFICULTY_MATRIX, BUSINESS_RISK_MATRIX, RISK_ORDER,
    combineDifficulty, computeAttackDifficultyForScenario, computeRiskForLetter, computeAllRisks,
  };
}
