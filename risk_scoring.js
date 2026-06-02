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

/** Maps ImplementationEffort values to cost weights used in efficiency calculation. */
const EFFORT_SCORE = { VeryLow: 1, Low: 3, Medium: 10, High: 30, VeryHigh: 100 };

/**
 * Business-risk levels used by the score table (NA and None are excluded —
 * they cannot improve or degrade in a meaningful way for this metric).
 */
const BUSINESS_RISK_SCORE_LEVELS = ['Low', 'Medium', 'High', 'Critical'];

/**
 * BUSINESS_RISK_SCORE_TABLE[updatedIdx][defaultIdx] = score increment.
 * Rows: updatedBusinessRisk (after applying the requirement — lower is better).
 * Cols: defaultBusinessRisk (before the requirement — the unmitigated baseline).
 * Non-zero only when the requirement actually reduces risk (updated < default).
 */
const BUSINESS_RISK_SCORE_TABLE = [
  // Cols: default=Low  Med  High  Crit
  /* updated=Low */     [0,   1,   3,   5],
  /* updated=Medium */  [0,   0,   2,   4],
  /* updated=High */    [0,   0,   0,   2],
  /* updated=Critical */[0,   0,   0,   0],
];

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

/**
 * Compute risk-reduction score and efficiency for one SecurityRequirement.
 * interactions – the full interactions array (passed in; risk_scoring has no globals).
 * Returns { score, efficiency } where efficiency = score / effortScore.
 *
 * For each RequirementInstance of secReq the algo:
 *   1. Skips interactions whose source/destination don't match the secReq's actors.
 *   2. Finds the max businessImpact for the STRIDE letter of the containing interaction.
 *   3. Computes defaultBusinessRisk from the TechnicalScenario's own tech+logs difficulty.
 *   4. Computes updatedBusinessRisk from THIS instance's own updatedTech/updatedLogs
 *      (not the combined effect of all requirements — that would make every requirement
 *      on the same TechnicalScenario produce an identical score).
 *      Instances with NA difficulties (unset placeholders) contribute nothing.
 *   5. Looks up the score increment in BUSINESS_RISK_SCORE_TABLE.
 */
function computeRequirementScores(secReq, interactions) {
  let score = 0;
  const effortScore = EFFORT_SCORE[secReq.effort] || 1;

  for (const ia of interactions) {
    if (ia.source !== secReq.source || ia.destination !== secReq.destination) continue;
    for (const l of ['s', 't', 'r', 'i', 'd', 'e']) {
      for (const ts of ia.attackDifficulty[l]) {
        for (const ri of ts.requirementInstances) {
          if (ri.secRequirement !== secReq) continue;

          // Placeholder instances (NA difficulties) are not yet filled in → skip
          if (ri.updatedTechDifficulty === 'NA' || ri.updatedLogisticsDifficulty === 'NA') continue;

          // Max business impact for this STRIDE letter
          let maxImpactIdx = -1;
          for (const bs of ia.businessImpact[l]) {
            const idx = SEVERITY.indexOf(bs.businessImpact);
            if (idx > maxImpactIdx) maxImpactIdx = idx;
          }
          if (maxImpactIdx < 0) continue; // no business scenarios → skip

          const defaultDiff = combineDifficulty(ts.technicalDifficulty, ts.logisticsDifficulty);
          // Use this instance's own updated difficulties so each requirement scores independently
          const updatedDiff = combineDifficulty(ri.updatedTechDifficulty, ri.updatedLogisticsDifficulty);
          if (defaultDiff === null || updatedDiff === null) continue;

          const defaultDiffIdx = ATTACK_DIFFICULTY.indexOf(defaultDiff);
          const updatedDiffIdx = ATTACK_DIFFICULTY.indexOf(updatedDiff);
          if (defaultDiffIdx < 0 || updatedDiffIdx < 0) continue;

          const defaultRisk = BUSINESS_RISK_MATRIX[maxImpactIdx][defaultDiffIdx];
          const updatedRisk = BUSINESS_RISK_MATRIX[maxImpactIdx][updatedDiffIdx];

          const dRiskIdx = BUSINESS_RISK_SCORE_LEVELS.indexOf(defaultRisk);
          const uRiskIdx = BUSINESS_RISK_SCORE_LEVELS.indexOf(updatedRisk);
          if (dRiskIdx < 0 || uRiskIdx < 0) continue; // NA or None → skip

          score += BUSINESS_RISK_SCORE_TABLE[uRiskIdx][dRiskIdx];
        }
      }
    }
  }
  return { score, efficiency: score / effortScore };
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
    SEVERITY, DIFFICULTY, ATTACK_DIFFICULTY, DIFFICULTY_MATRIX, BUSINESS_RISK_MATRIX,
    RISK_ORDER, EFFORT_SCORE, BUSINESS_RISK_SCORE_LEVELS, BUSINESS_RISK_SCORE_TABLE,
    combineDifficulty, computeAttackDifficultyForScenario,
    computeRequirementScores, computeRiskForLetter, computeAllRisks,
  };
}
