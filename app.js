// ============================================================
// LiteTM — Lightweight Threat Modeling Tool  (v0.63)
// Scoring logic lives in risk_scoring.js (SEVERITY, DIFFICULTY,
// matrices, combineDifficulty, computeRiskForLetter, computeAllRisks,
// RISK_ORDER) — all available as globals when loaded before this file.
// ============================================================

const STRIDE_LETTERS = ['s', 't', 'r', 'i', 'd', 'e'];

/** STRIDE letter → full category name (spec §Business logic §STRIDE mappings) */
const STRIDE_NAMES = {
  s: 'Spoofing',
  t: 'Tampering',
  r: 'Repudiation',
  i: 'Information Disclosure',
  d: 'Denial of Service',
  e: 'Elevation of Privilege',
};

/** STRIDE letter → definition from STRIDE_definitions.md (Microsoft) */
const STRIDE_DEFINITIONS = {
  s: 'Involves illegally accessing and then using another user\'s authentication information, such as username and password',
  t: 'Involves the malicious modification of data. Examples include unauthorized changes made to persistent data, such as that held in a database, and the alteration of data as it flows between two computers over an open network, such as the Internet',
  r: 'Associated with users who deny performing an action without other parties having any way to prove otherwise—for example, a user performs an illegal operation in a system that lacks the ability to trace the prohibited operations. Non-Repudiation refers to the ability of a system to counter repudiation threats.',
  i: 'Involves the exposure of information to individuals who are not supposed to have access to it—for example, the ability of users to read a file that they were not granted access to, or the ability of an intruder to read data in transit between two computers',
  d: 'Denial of service (DoS) attacks deny service to valid users—for example, by making a Web server temporarily unavailable or unusable. You must protect against certain types of DoS threats simply to improve system availability and reliability',
  e: 'An unprivileged user gains privileged access and thereby has sufficient access to compromise or destroy the entire system. Elevation of privilege threats include those situations in which an attacker has effectively penetrated all system defenses and become part of the trusted system itself, a dangerous situation indeed',
};

/** Returns a generic ⓘ icon with a Bootstrap tooltip showing any message. */
function infoIconHtml(message) {
  return `<span class="help-icon" data-bs-toggle="tooltip" data-bs-placement="auto" data-bs-title="${escapeHtml(message)}">ⓘ</span>`;
}

/** Returns an ⓘ icon with the STRIDE definition for a given letter. */
function helpIconHtml(letter) {
  return infoIconHtml(STRIDE_DEFINITIONS[letter]);
}

const HELP_BUSINESS_IMPACT   = 'Supposing such attack is possible, what would be the business impact?';
const HELP_ATTACK_DIFFICULTY = 'Estimate the complexity to execute such attack';

const IMPLEMENTATION_EFFORT = ['VeryLow', 'Low', 'Medium', 'High', 'VeryHigh'];

const REQUIREMENT_STATUS = ['NA', 'Backlog', 'Planned', 'Implemented'];

/**
 * Single-pass regex: matches either an HTML tag (returned unchanged) or a STRIDE
 * category name (appended with a help icon). Skipping tags prevents matching text
 * inside attribute values such as data-bs-title.
 */
const STRIDE_MENTION_RE = /<[^>]*>|Spoofing|Tampering|Repudiation|Information [Dd]isclosure|Denial of [Ss]ervice|E(?:levation|scalation) of [Pp]rivilege/g;

function letterForMention(name) {
  const l = name.toLowerCase();
  if (l === 'spoofing')            return 's';
  if (l === 'tampering')           return 't';
  if (l === 'repudiation')         return 'r';
  if (l.startsWith('information')) return 'i';
  if (l.startsWith('denial'))      return 'd';
  return 'e';
}

/** Initialises Bootstrap tooltips on all [data-bs-toggle="tooltip"] inside container. */
function initTooltips(container) {
  container.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    bootstrap.Tooltip.getOrCreateInstance(el, { customClass: 'help-tooltip' });
  });
}

/** Hex colour per BusinessRisk level — used for STRIDE badges and message-text tinting. */
const RISK_COLORS = {
  NA:       null,
  None:     '#198754',
  Low:      '#ffc107',
  Medium:   '#fd7e14',
  High:     '#dc3545',
  Critical: '#6f42c1',
};

// ============================================================
// Application State
// ============================================================

let interactions    = [];  // Array of Interaction objects
let diagramMarkdown = '';  // Raw markdown currently displayed
let renderCount     = 0;   // Unique ID counter for mermaid.render() calls

/**
 * Context for the currently open STRIDE modal.
 * page:      'main' | 'newBusiness' | 'newTech'
 * editIndex: -1 = creating a new scenario; ≥0 = editing existing at that index
 */
let modalCtx = {
  interactionIndex: -1,
  letter: '',
  page: 'main',
  editIndex: -1,
  reqEditIndex: -1,
};

/** Sort state for the Security Requirements Summary table. */
let tableSort = { col: null, asc: true };

/** Stable reference list used by table row onclick handlers (rebuilt on each render). */
let _currentSecReqs = [];

/** SecurityRequirement currently being edited via the table's Edit modal. */
let editSecReqTarget = null;

// Bootstrap modal instances — initialised in DOMContentLoaded
let bsStrideModal;
let bsImportModal;
let bsExportModal;
let bsCrashCourseModal;
let bsRiskScoringModal;
let bsEditSecReqModal;

// ============================================================
// Sequence Diagram Parser
// ============================================================

function emptyStrideMap() {
  return { s: [], t: [], r: [], i: [], d: [], e: [] };
}

function makeInteraction(source, destination, label) {
  return {
    source,
    destination,
    label,
    businessImpact:   emptyStrideMap(),
    attackDifficulty: emptyStrideMap(),
    risks: { s: 'NA', t: 'NA', r: 'NA', i: 'NA', d: 'NA', e: 'NA' },
  };
}

function parseSequenceDiagram(markdown) {
  const lines   = markdown.split('\n');
  const parsed  = [];
  const aliases = {}; // id → display name

  // Keywords that open structural blocks — skip these lines entirely
  const skipRe = /^(note|loop|alt|else|end|opt|par|and|critical|break|rect|activate|deactivate|autonumber|sequenceDiagram)\b/i;

  // Mermaid arrow types — longest patterns first to avoid partial matches
  const arrowRe = /^(.+?)\s*(-->>|--x|-->|--\)|->>|-x|->|-\))\s*([+-]?)(.+?)\s*:\s*(.*)$/;

  // participant / actor declarations
  const participantRe = /^(?:participant|actor)\s+(\S+)(?:\s+as\s+(.+))?$/i;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('%')) continue;
    if (skipRe.test(line)) continue;

    const pMatch = line.match(participantRe);
    if (pMatch) {
      const id   = pMatch[1].trim();
      const name = pMatch[2] ? pMatch[2].trim() : id;
      aliases[id] = name;
      continue;
    }

    const aMatch = line.match(arrowRe);
    if (aMatch) {
      const srcRaw = aMatch[1].trim();
      const dstRaw = aMatch[4].trim();
      parsed.push(makeInteraction(
        aliases[srcRaw] || srcRaw,
        aliases[dstRaw] || dstRaw,
        aMatch[5].trim()
      ));
    }
  }

  return parsed;
}

// ============================================================
// Diagram Rendering & STRIDE Overlay
// ============================================================

/** Inject an already-rendered SVG string into the diagram panel. */
function displaySvg(svg) {
  document.getElementById('diagramContainer').innerHTML = svg;
  document.getElementById('diagramWrapper').style.display = 'block';
  document.getElementById('emptyState').style.display    = 'none';
}

function riskClass(risk) {
  const map = {
    NA:       'stride-na',
    None:     'stride-none',
    Low:      'stride-low',
    Medium:   'stride-medium',
    High:     'stride-high',
    Critical: 'stride-critical',
  };
  return map[risk] || 'stride-na';
}

function needsQuestionMark(interaction, letter) {
  return interaction.businessImpact[letter].length > 0 && interaction.risks[letter] === 'NA';
}

function needsExclamationMark(interaction, letter) {
  return interaction.attackDifficulty[letter].some(ts =>
    ts.requirementInstances.some(ri =>
      ri.updatedTechDifficulty === 'NA' || ri.updatedLogisticsDifficulty === 'NA'
    )
  );
}

function buildAnnotationDiv(interaction, idx) {
  const div = document.createElement('div');
  div.className = 'stride-annotation';
  div.dataset.interactionIndex = idx;

  STRIDE_LETTERS.forEach(letter => {
    const cell = document.createElement('span');
    cell.className = 'stride-letter-cell';

    const badge = document.createElement('span');
    badge.textContent = letter.toUpperCase();
    badge.title       = STRIDE_NAMES[letter];
    badge.className   = `stride-letter ${riskClass(interaction.risks[letter])}`;
    badge.addEventListener('click', () => openStrideModal(idx, letter));
    cell.appendChild(badge);

    if (needsQuestionMark(interaction, letter)) {
      const q = document.createElement('span');
      q.className   = 'stride-question';
      q.textContent = '?';
      cell.appendChild(q);
    }

    if (needsExclamationMark(interaction, letter)) {
      const ex = document.createElement('span');
      ex.className   = 'stride-exclamation';
      ex.textContent = '!';
      cell.appendChild(ex);
    }

    div.appendChild(cell);
  });

  return div;
}

function injectStrideOverlays() {
  const overlay = document.getElementById('strideOverlay');
  overlay.innerHTML = '';

  const svg = document.querySelector('#diagramContainer svg');
  if (!svg) return;

  const msgTexts = Array.from(svg.querySelectorAll('text.messageText'));
  if (!msgTexts.length) return;

  const wrapperRect = document.getElementById('diagramWrapper').getBoundingClientRect();

  interactions.forEach((interaction, idx) => {
    const el = msgTexts[idx];
    if (!el) return;

    const rect = el.getBoundingClientRect();
    const div  = buildAnnotationDiv(interaction, idx);
    div.style.left = (rect.left - wrapperRect.left + rect.width / 2) + 'px';
    div.style.top  = (rect.bottom - wrapperRect.top + 4) + 'px';

    overlay.appendChild(div);
  });
}

/** Update colour classes and ? indicators on an already-rendered annotation row. */
function refreshAnnotationColors(interactionIndex) {
  const overlay = document.getElementById('strideOverlay');
  const div = overlay.querySelector(`[data-interaction-index="${interactionIndex}"]`);
  if (!div) return;

  const interaction = interactions[interactionIndex];
  const cells = div.querySelectorAll('.stride-letter-cell');
  cells.forEach((cell, i) => {
    const letter = STRIDE_LETTERS[i];
    cell.querySelector('.stride-letter').className = `stride-letter ${riskClass(interaction.risks[letter])}`;

    const existing = cell.querySelector('.stride-question');
    if (needsQuestionMark(interaction, letter)) {
      if (!existing) {
        const q = document.createElement('span');
        q.className   = 'stride-question';
        q.textContent = '?';
        cell.appendChild(q);
      }
    } else {
      existing?.remove();
    }

    const existingEx = cell.querySelector('.stride-exclamation');
    if (needsExclamationMark(interaction, letter)) {
      if (!existingEx) {
        const ex = document.createElement('span');
        ex.className   = 'stride-exclamation';
        ex.textContent = '!';
        cell.appendChild(ex);
      }
    } else {
      existingEx?.remove();
    }
  });
}

// ============================================================
// Message-text Coloring
// ============================================================

/** Returns the highest BusinessRisk across all 6 STRIDE letters for one interaction. */
function getInteractionMaxRisk(interaction) {
  let maxIdx = 0;
  for (const letter of STRIDE_LETTERS) {
    const idx = RISK_ORDER.indexOf(interaction.risks[letter]);
    if (idx > maxIdx) maxIdx = idx;
  }
  return RISK_ORDER[maxIdx];
}

/**
 * Tint the SVG message-text label above one arrow.
 * The text.messageText elements are the exact same ones injectStrideOverlays()
 * uses, so the indices correspond 1-to-1 with interactions[].
 */
function updateMessageTextColor(interactionIndex) {
  const svg = document.querySelector('#diagramContainer svg');
  if (!svg) return;

  const msgTexts = Array.from(svg.querySelectorAll('text.messageText'));
  const el = msgTexts[interactionIndex];
  if (!el) return;

  const interaction = interactions[interactionIndex];
  const hasQuestionMark = STRIDE_LETTERS.some(l => needsQuestionMark(interaction, l));
  if (hasQuestionMark) {
    el.style.fill = '';
    return;
  }

  const color = RISK_COLORS[getInteractionMaxRisk(interaction)];
  el.style.fill = color ?? '';   // null (NA) → clear → browser default (black)
}

/** Tint every message-text label to match the current max-risk of its interaction. */
function colorAllMessageTexts() {
  interactions.forEach((_, idx) => updateMessageTextColor(idx));
}

// ============================================================
// Coverage Score
// ============================================================

function updateCoverageScore() {
  const total = interactions.length * STRIDE_LETTERS.length;
  const el    = document.getElementById('coverageScore');
  if (total === 0) { el.style.display = 'none'; return; }

  let scored = 0;
  for (const interaction of interactions) {
    for (const letter of STRIDE_LETTERS) {
      if (interaction.risks[letter] !== 'NA') scored++;
    }
  }
  document.getElementById('coverageScoreValue').textContent =
    (scored / total * 100).toFixed(1) + '%';
  el.style.display = '';
}

// ============================================================
// Security Requirements Table
// ============================================================

/** Collect every unique SecurityRequirement object from all interactions. */
function collectAllSecRequirements() {
  const seen = new Set();
  const list = [];
  for (const ia of interactions) {
    for (const l of STRIDE_LETTERS) {
      for (const ts of ia.attackDifficulty[l]) {
        for (const ri of ts.requirementInstances) {
          if (!seen.has(ri.secRequirement)) {
            seen.add(ri.secRequirement);
            list.push(ri.secRequirement);
          }
        }
      }
    }
  }
  return list;
}

/**
 * Apply current tableSort to an array of row objects { req, score, efficiency }.
 * Risk/Efficiency cols use a split sort: non-Implemented rows first, Implemented last.
 */
function sortSecReqRows(rows) {
  const { col, asc } = tableSort;
  if (!col) return rows;
  const dir = asc ? 1 : -1;

  const cmp = (a, b) => {
    switch (col) {
      case 'title':
        return dir * a.req.title.toLowerCase().localeCompare(b.req.title.toLowerCase());
      case 'effort':
        return dir * (IMPLEMENTATION_EFFORT.indexOf(a.req.effort) -
                      IMPLEMENTATION_EFFORT.indexOf(b.req.effort));
      case 'status': {
        const ai = REQUIREMENT_STATUS.indexOf(a.req.status || 'NA');
        const bi = REQUIREMENT_STATUS.indexOf(b.req.status || 'NA');
        return dir * (ai - bi);
      }
      case 'risk':       return dir * (a.score      - b.score);
      case 'efficiency': return dir * (a.efficiency - b.efficiency);
      default: return 0;
    }
  };

  if (col === 'risk' || col === 'efficiency') {
    const notImpl = rows.filter(r => (r.req.status || 'NA') !== 'Implemented');
    const impl    = rows.filter(r => (r.req.status || 'NA') === 'Implemented');
    return [...notImpl.sort(cmp), ...impl.sort(cmp)];
  }
  return [...rows].sort(cmp);
}

function buildSecReqTableHtml() {
  _currentSecReqs = collectAllSecRequirements();
  if (_currentSecReqs.length === 0) return '';

  // Precompute scores then sort (keep original index for onclick references)
  const rowData = _currentSecReqs.map((req, idx) => {
    const { score, efficiency } = computeRequirementScores(req, interactions);
    return { req, idx, score, efficiency };
  });
  const sorted = sortSecReqRows(rowData);

  const COL_DEFS = [
    { key: 'title',      label: 'Title',                 sortable: true  },
    { key: 'desc',       label: 'Description',           sortable: false },
    { key: 'effort',     label: 'Implementation Effort', sortable: true  },
    { key: 'status',     label: 'Status',                sortable: true  },
    { key: 'risk',       label: 'Risk Reduction',        sortable: true  },
    { key: 'efficiency', label: 'Efficiency Score',      sortable: true  },
  ];

  const headerCells = COL_DEFS.map(col => {
    if (!col.sortable) return `<th>${col.label}</th>`;
    const active = tableSort.col === col.key;
    const arrow  = active ? (tableSort.asc ? ' ▲' : ' ▼') : ' ⇅';
    return `<th style="cursor:pointer;user-select:none"
                onclick="app.sortSecReqTable('${col.key}')">${col.label}${arrow}</th>`;
  }).join('');

  const bodyRows = sorted.map(({ req, idx, score, efficiency }) => {
    const implemented = (req.status || 'NA') === 'Implemented';
    return `
    <tr${implemented ? ' class="table-secondary"' : ''}>
      <td>
        <div>${escapeHtml(req.title)}</div>
        <div class="d-flex gap-1 mt-1">
          <button class="btn btn-sm btn-outline-secondary py-0"
                  onclick="app.editSecReq(${idx})" title="Edit">✏️</button>
          <button class="btn btn-sm btn-outline-danger py-0"
                  onclick="app.deleteSecReq(${idx})" title="Delete">🗑</button>
          <button class="btn btn-sm py-0 ${req.active !== false ? 'btn-success' : 'btn-outline-secondary'}"
                  onclick="app.toggleSecReq(${idx})"
                  title="${req.active !== false ? 'Active — click to deactivate' : 'Inactive — click to activate'}"
                  >${req.active !== false ? 'ON' : 'OFF'}</button>
        </div>
      </td>
      <td>${escapeHtml(req.description || '')}</td>
      <td>${escapeHtml(req.effort)}</td>
      <td>${escapeHtml(req.status || 'NA')}</td>
      <td>${score}</td>
      <td>${efficiency.toFixed(2)}</td>
    </tr>`;
  }).join('');

  return `
    <h6 class="fw-semibold mt-4 mb-2">Security Requirements Summary</h6>
    <div class="table-responsive">
      <table class="table table-sm table-bordered table-hover mb-0">
        <thead class="table-light"><tr>${headerCells}</tr></thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>`;
}

function updateSecReqTable() {
  document.getElementById('secReqTable').innerHTML = buildSecReqTableHtml();
}

// ============================================================
// STRIDE Modal
// ============================================================

function openStrideModal(interactionIndex, letter) {
  modalCtx = { interactionIndex, letter, page: 'main', editIndex: -1 };
  renderStrideModalContent();
  bsStrideModal.show();
}

function closeStrideModal() {
  const idx = modalCtx.interactionIndex;
  interactions[idx].risks = computeAllRisks(interactions[idx]);
  updateMessageTextColor(idx);
  // Sync secRequirements to all matching interactions, then refresh every annotation
  // (covers risk colours, ? marks and ! marks across all interactions at once)
  syncAllForInteraction(idx);
  interactions.forEach((_, i) => refreshAnnotationColors(i));
  updateCoverageScore();
  updateSecReqTable();
  bsStrideModal.hide();
}

function renderStrideModalContent() {
  const interaction = interactions[modalCtx.interactionIndex];
  const { letter, page, editIndex } = modalCtx;

  const titleEl  = document.getElementById('strideModalTitle');
  const bodyEl   = document.getElementById('strideModalBody');
  const footerEl = document.getElementById('strideModalFooter');

  // ── Main list page ─────────────────────────────────────────
  if (page === 'main') {
    titleEl.innerHTML = `${escapeHtml(STRIDE_NAMES[letter])} ${helpIconHtml(letter)}`;

    const biz  = interaction.businessImpact[letter];
    const tech = interaction.attackDifficulty[letter];

    bodyEl.innerHTML = `
      <h6 class="fw-semibold text-primary">Business Impact Scenarios</h6>
      <div id="bizList">
        ${biz.length === 0
          ? '<p class="text-muted small fst-italic mb-1">No scenarios added yet.</p>'
          : biz.map((s, i) => `
            <div class="scenario-row">
              <div class="flex-grow-1">
                <span class="fw-medium">${escapeHtml(s.title)}</span>
                <span class="badge bg-secondary ms-2">${escapeHtml(s.businessImpact)}</span>
                ${s.description ? `<br><small class="text-muted">${escapeHtml(s.description)}</small>` : ''}
              </div>
              <div class="d-flex gap-1 flex-shrink-0">
                <button class="btn btn-sm btn-outline-secondary"
                        onclick="app.editBusinessScenario(${i})" title="Edit">✏️</button>
                <button class="btn btn-sm btn-outline-danger"
                        onclick="app.deleteBusinessScenario(${i})" title="Delete">🗑</button>
              </div>
            </div>`).join('')
        }
      </div>
      <div class="d-flex align-items-center gap-2 mt-2 mb-4">
        <button class="btn btn-sm btn-outline-success"
                onclick="app.showNewBusinessForm()">+ Add Business Impact Scenario</button>
        ${infoIconHtml(HELP_BUSINESS_IMPACT)}
      </div>

      <hr class="my-2">

      <h6 class="fw-semibold text-primary mt-3">Attack Scenarios</h6>
      <div id="techList">
        ${tech.length === 0
          ? '<p class="text-muted small fst-italic mb-1">No scenarios added yet.</p>'
          : tech.map((t, i) => `
            <div class="scenario-row">
              <div class="flex-grow-1">
                <span class="fw-medium">${escapeHtml(t.title)}</span>
                <span class="badge bg-secondary ms-2">Tech: ${escapeHtml(t.technicalDifficulty)}</span>
                <span class="badge bg-secondary ms-1">Log: ${escapeHtml(t.logisticsDifficulty)}</span>
                ${t.description ? `<br><small class="text-muted">${escapeHtml(t.description)}</small>` : ''}
              </div>
              <div class="d-flex gap-1 flex-shrink-0">
                <button class="btn btn-sm btn-outline-secondary"
                        onclick="app.editTechnicalScenario(${i})" title="Edit">✏️</button>
                <button class="btn btn-sm btn-outline-danger"
                        onclick="app.deleteTechnicalScenario(${i})" title="Delete">🗑</button>
              </div>
            </div>`).join('')
        }
      </div>
      <div class="d-flex align-items-center gap-2 mt-2">
        <button class="btn btn-sm btn-outline-success"
                onclick="app.showNewTechForm()">+ Add Attack Scenario</button>
        ${infoIconHtml(HELP_ATTACK_DIFFICULTY)}
      </div>

      <hr class="my-2">

      <h6 class="fw-semibold text-primary mt-3">Resulting Risk</h6>
      <p class="mb-0">
        <span class="stride-letter ${riskClass(computeRiskForLetter(biz, tech))}"
              style="font-size:0.85rem;padding:3px 10px;">
          ${computeRiskForLetter(biz, tech)}
        </span>
      </p>
    `;

    footerEl.innerHTML = `
      <button type="button" class="btn btn-primary" id="strideCloseBtn">Close</button>
    `;
    document.getElementById('strideCloseBtn').addEventListener('click', closeStrideModal);
    initTooltips(document.getElementById('strideModal'));

  // ── BusinessScenario form (create or edit) ─────────────────
  } else if (page === 'newBusiness') {
    const isEdit   = editIndex >= 0;
    const existing = isEdit ? interaction.businessImpact[letter][editIndex] : null;

    titleEl.innerHTML = `Business Impact scenario for ${escapeHtml(STRIDE_NAMES[letter])} ${infoIconHtml(HELP_BUSINESS_IMPACT)}`;

    bodyEl.innerHTML = `
      <div class="mb-3">
        <label class="form-label fw-medium">Title <span class="text-danger">*</span></label>
        <input type="text" class="form-control" id="bizTitle"
               value="${existing ? escapeHtml(existing.title) : ''}"
               placeholder="e.g. Attacker impersonates a legitimate user">
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Description</label>
        <textarea class="form-control" id="bizDescription" rows="3"
                  placeholder="Describe what the attacker could achieve…">${existing ? escapeHtml(existing.description) : ''}</textarea>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Business Impact</label>
        <select class="form-select" id="bizImpact">
          ${SEVERITY.map(s =>
            `<option value="${s}"${existing && existing.businessImpact === s ? ' selected' : ''}>${s}</option>`
          ).join('')}
        </select>
      </div>
    `;

    footerEl.innerHTML = `
      <button type="button" class="btn btn-secondary" id="bizBackBtn">← Back</button>
      <button type="button" class="btn btn-primary"   id="bizSaveBtn">${isEdit ? 'Update Scenario' : 'Save Scenario'}</button>
    `;
    document.getElementById('bizBackBtn').addEventListener('click', () => {
      modalCtx.page = 'main';
      renderStrideModalContent();
    });
    document.getElementById('bizSaveBtn').addEventListener('click', saveBusinessScenario);
    initTooltips(document.getElementById('strideModal'));

  // ── TechnicalScenario form (create or edit) ────────────────
  } else if (page === 'newTech') {
    const isEdit   = editIndex >= 0;
    const existing = isEdit ? interaction.attackDifficulty[letter][editIndex] : null;
    const reqs     = isEdit ? (existing.requirementInstances || []) : [];

    titleEl.innerHTML = `Attack scenario for ${escapeHtml(STRIDE_NAMES[letter])} ${infoIconHtml(HELP_ATTACK_DIFFICULTY)}`;

    let reqRowsHtml = '';
    if (isEdit) {
      reqRowsHtml = reqs.length === 0
        ? '<p class="text-muted small fst-italic mb-1">No security requirements added yet.</p>'
        : reqs.map((ri, i) => `
            <div class="scenario-row">
              <div class="flex-grow-1">
                <span class="fw-medium">${escapeHtml(ri.secRequirement.title)}</span>
                <br><small class="text-muted">Tech: <span${ri.updatedTechDifficulty === 'NA' ? ' class="text-danger fw-semibold"' : ''}>${escapeHtml(ri.updatedTechDifficulty)}</span> / Log: <span${ri.updatedLogisticsDifficulty === 'NA' ? ' class="text-danger fw-semibold"' : ''}>${escapeHtml(ri.updatedLogisticsDifficulty)}</span></small>
                ${ri.secRequirement.description ? `<br><small class="text-muted">${escapeHtml(ri.secRequirement.description)}</small>` : ''}
              </div>
              <div class="d-flex gap-1 flex-shrink-0">
                <button class="btn btn-sm btn-outline-secondary" onclick="app.editRequirement(${i})" title="Edit">✏️</button>
                <button class="btn btn-sm btn-outline-danger" onclick="app.deleteRequirement(${i})" title="Delete">🗑</button>
              </div>
            </div>`).join('');
    }

    const attackDiff = isEdit ? (computeAttackDifficultyForScenario(existing) || 'N/A') : null;

    const requirementsSectionHtml = isEdit ? `
        <hr class="my-3">
        <h6 class="fw-semibold text-secondary">Security Requirements</h6>
        <div id="reqList">${reqRowsHtml}</div>
        <div class="mt-2">
          <button class="btn btn-sm btn-outline-primary" onclick="app.showNewRequirementForm()">+ Create Security Requirement</button>
        </div>
        <hr class="my-2">
        <p class="mb-0">Resulting attack difficulty: <strong>${escapeHtml(attackDiff)}</strong></p>` : '';

    bodyEl.innerHTML = `
      <div class="mb-3">
        <label class="form-label fw-medium">Title <span class="text-danger">*</span></label>
        <input type="text" class="form-control" id="techTitle"
               value="${existing ? escapeHtml(existing.title) : ''}"
               placeholder="e.g. Replay a captured authentication token">
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Description</label>
        <textarea class="form-control" id="techDescription" rows="3"
                  placeholder="Describe the attack technique…">${existing ? escapeHtml(existing.description) : ''}</textarea>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Technical Difficulty</label>
        <select class="form-select" id="techDiff">
          ${DIFFICULTY.map(d =>
            `<option value="${d}"${existing && existing.technicalDifficulty === d ? ' selected' : ''}>${d}</option>`
          ).join('')}
        </select>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Logistics Difficulty</label>
        <select class="form-select" id="logsDiff">
          ${DIFFICULTY.map(d =>
            `<option value="${d}"${existing && existing.logisticsDifficulty === d ? ' selected' : ''}>${d}</option>`
          ).join('')}
        </select>
      </div>
      ${requirementsSectionHtml}
    `;

    footerEl.innerHTML = `
      <button type="button" class="btn btn-secondary" id="techBackBtn">← Back</button>
      <button type="button" class="btn btn-primary"   id="techSaveBtn">${isEdit ? 'Update Scenario' : 'Save Scenario'}</button>
    `;
    document.getElementById('techBackBtn').addEventListener('click', () => {
      modalCtx.page = 'main';
      renderStrideModalContent();
    });
    document.getElementById('techSaveBtn').addEventListener('click', saveTechnicalScenario);
    initTooltips(document.getElementById('strideModal'));

  // ── SecurityRequirement form (create or edit) ────────────────
  } else if (page === 'newRequirement') {
    const isEdit      = modalCtx.reqEditIndex >= 0;
    const techScenario = interaction.attackDifficulty[letter][editIndex];
    const existingReq  = isEdit ? techScenario.requirementInstances[modalCtx.reqEditIndex] : null;

    titleEl.innerHTML = `Security Requirement for ${escapeHtml(STRIDE_NAMES[letter])}`;

    bodyEl.innerHTML = `
      <h6 class="fw-semibold text-primary mb-3">Security Requirement</h6>
      <div class="mb-3">
        <label class="form-label fw-medium">Title <span class="text-danger">*</span></label>
        <input type="text" class="form-control" id="reqTitle"
               value="${existingReq ? escapeHtml(existingReq.secRequirement.title) : ''}"
               placeholder="e.g. Implement token expiry">
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Description</label>
        <textarea class="form-control" id="reqDescription" rows="3"
                  placeholder="Describe the security control…">${existingReq ? escapeHtml(existingReq.secRequirement.description) : ''}</textarea>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Implementation Effort</label>
        <select class="form-select" id="reqEffort">
          ${IMPLEMENTATION_EFFORT.map(ef =>
            `<option value="${ef}"${existingReq && existingReq.secRequirement.effort === ef ? ' selected' : ''}>${ef}</option>`
          ).join('')}
        </select>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Status</label>
        <select class="form-select" id="reqStatus">
          ${REQUIREMENT_STATUS.map(s =>
            `<option value="${s}"${existingReq && existingReq.secRequirement.status === s ? ' selected' : ''}>${s}</option>`
          ).join('')}
        </select>
      </div>

      <hr class="my-3">

      <h6 class="fw-semibold text-primary mb-3">For this attack scenario</h6>
      <div class="mb-3">
        <label class="form-label fw-medium">Updated Technical Difficulty</label>
        <select class="form-select" id="reqTechDiff">
          ${ATTACK_DIFFICULTY.map(d =>
            `<option value="${d}"${existingReq && existingReq.updatedTechDifficulty === d ? ' selected' : ''}>${d}</option>`
          ).join('')}
        </select>
      </div>
      <div class="mb-3">
        <label class="form-label fw-medium">Updated Logistics Difficulty</label>
        <select class="form-select" id="reqLogsDiff">
          ${ATTACK_DIFFICULTY.map(d =>
            `<option value="${d}"${existingReq && existingReq.updatedLogisticsDifficulty === d ? ' selected' : ''}>${d}</option>`
          ).join('')}
        </select>
      </div>
    `;

    footerEl.innerHTML = `
      <button type="button" class="btn btn-secondary" id="reqBackBtn">← Back</button>
      <button type="button" class="btn btn-primary"   id="reqSaveBtn">${isEdit ? 'Update Requirement' : 'Save Requirement'}</button>
    `;
    document.getElementById('reqBackBtn').addEventListener('click', () => {
      modalCtx.page = 'newTech';
      modalCtx.reqEditIndex = -1;
      renderStrideModalContent();
    });
    document.getElementById('reqSaveBtn').addEventListener('click', saveRequirement);
    initTooltips(document.getElementById('strideModal'));
  }
}

// ── Save / update handlers ─────────────────────────────────────

function saveBusinessScenario() {
  const titleInput = document.getElementById('bizTitle');
  const title = titleInput.value.trim();
  if (!title) {
    titleInput.classList.add('is-invalid');
    return;
  }

  const scenario = {
    title,
    description:    document.getElementById('bizDescription').value.trim(),
    businessImpact: document.getElementById('bizImpact').value,
  };

  const list = interactions[modalCtx.interactionIndex].businessImpact[modalCtx.letter];
  if (modalCtx.editIndex >= 0) {
    list[modalCtx.editIndex] = scenario;   // update existing
  } else {
    list.push(scenario);                   // add new
  }

  modalCtx.page = 'main';
  modalCtx.editIndex = -1;
  renderStrideModalContent();
}

function saveTechnicalScenario() {
  const titleInput = document.getElementById('techTitle');
  const title = titleInput.value.trim();
  if (!title) {
    titleInput.classList.add('is-invalid');
    return;
  }

  const list     = interactions[modalCtx.interactionIndex].attackDifficulty[modalCtx.letter];
  const existing = modalCtx.editIndex >= 0 ? list[modalCtx.editIndex] : null;

  const scenario = {
    title,
    description:          document.getElementById('techDescription').value.trim(),
    technicalDifficulty:  document.getElementById('techDiff').value,
    logisticsDifficulty:  document.getElementById('logsDiff').value,
    requirementInstances: existing ? existing.requirementInstances : [],
  };

  if (modalCtx.editIndex >= 0) {
    list[modalCtx.editIndex] = scenario;
  } else {
    list.push(scenario);
  }

  modalCtx.page = 'main';
  modalCtx.editIndex = -1;
  renderStrideModalContent();
}

/**
 * Syncing interactions (spec §): for one secRequirement and one actor pair (src→dst),
 * add a placeholder RequirementInstance (NA difficulties) to every TechnicalScenario
 * of every matching Interaction that doesn't already reference this secRequirement.
 */
function syncInteractions(src, dst, secReq, originTs) {
  for (const ia of interactions) {
    if (ia.source !== src || ia.destination !== dst) continue;
    for (const l of STRIDE_LETTERS) {
      for (const ts of ia.attackDifficulty[l]) {
        if (!ts.requirementInstances.some(ri => ri.secRequirement === secReq)) {
          ts.requirementInstances.push({
            secRequirement:             secReq,
            techScenario:               originTs,               // back-ref; excluded from JSON export
            updatedTechDifficulty:      'NA',
            updatedLogisticsDifficulty: 'NA',
          });
        }
      }
    }
  }
}

/**
 * Called when a TechnicalScenario is saved: collects every secRequirement already
 * referenced by any matching Interaction and runs syncInteractions for each,
 * so the new/edited scenario inherits all pre-existing security requirements.
 */
function syncAllForInteraction(interactionIdx) {
  const src  = interactions[interactionIdx].source;
  const dst  = interactions[interactionIdx].destination;
  const seen = new Map(); // secReq → originTs

  for (const ia of interactions) {
    if (ia.source !== src || ia.destination !== dst) continue;
    for (const l of STRIDE_LETTERS) {
      for (const ts of ia.attackDifficulty[l]) {
        for (const ri of ts.requirementInstances) {
          if (!seen.has(ri.secRequirement)) {
            // ri.techScenario is the origin if already stamped, otherwise the containing ts
            seen.set(ri.secRequirement, ri.techScenario || ts);
          }
        }
      }
    }
  }

  for (const [secReq, originTs] of seen) syncInteractions(src, dst, secReq, originTs);
}

function saveRequirement() {
  const titleInput = document.getElementById('reqTitle');
  const title = titleInput.value.trim();
  if (!title) {
    titleInput.classList.add('is-invalid');
    return;
  }

  const interaction  = interactions[modalCtx.interactionIndex];
  const techScenario = interaction.attackDifficulty[modalCtx.letter][modalCtx.editIndex];

  if (modalCtx.reqEditIndex >= 0) {
    // Mutate in place so every RequirementInstance that shares this secRequirement
    // object reference (propagated placeholders) sees the updated metadata without
    // syncAllForInteraction treating the old reference as a separate requirement.
    const inst = techScenario.requirementInstances[modalCtx.reqEditIndex];
    inst.secRequirement.title       = title;
    inst.secRequirement.description = document.getElementById('reqDescription').value.trim();
    inst.secRequirement.effort      = document.getElementById('reqEffort').value;
    inst.secRequirement.status      = document.getElementById('reqStatus').value;
    inst.updatedTechDifficulty      = document.getElementById('reqTechDiff').value;
    inst.updatedLogisticsDifficulty = document.getElementById('reqLogsDiff').value;
  } else {
    techScenario.requirementInstances.push({
      secRequirement: {
        title,
        description:  document.getElementById('reqDescription').value.trim(),
        source:       interaction.source,
        destination:  interaction.destination,
        effort:       document.getElementById('reqEffort').value,
        status:       document.getElementById('reqStatus').value,
        active:       true,
      },
      techScenario,                                              // back-ref; excluded from JSON export
      updatedTechDifficulty:      document.getElementById('reqTechDiff').value,
      updatedLogisticsDifficulty: document.getElementById('reqLogsDiff').value,
    });
  }

  modalCtx.page = 'newTech';
  modalCtx.reqEditIndex = -1;
  renderStrideModalContent();
}

// ── app object — exposed to inline onclick= handlers ──────────

const app = {
  showNewBusinessForm() {
    modalCtx.editIndex = -1;
    modalCtx.page = 'newBusiness';
    renderStrideModalContent();
  },
  showNewTechForm() {
    modalCtx.editIndex = -1;
    modalCtx.page = 'newTech';
    renderStrideModalContent();
  },
  editBusinessScenario(index) {
    modalCtx.editIndex = index;
    modalCtx.page = 'newBusiness';
    renderStrideModalContent();
  },
  editTechnicalScenario(index) {
    modalCtx.editIndex = index;
    modalCtx.page = 'newTech';
    renderStrideModalContent();
  },
  deleteBusinessScenario(index) {
    interactions[modalCtx.interactionIndex].businessImpact[modalCtx.letter].splice(index, 1);
    renderStrideModalContent();
  },
  deleteTechnicalScenario(index) {
    interactions[modalCtx.interactionIndex].attackDifficulty[modalCtx.letter].splice(index, 1);
    renderStrideModalContent();
  },
  editSecReq(idx) {
    editSecReqTarget = _currentSecReqs[idx];
    if (!editSecReqTarget) return;
    document.getElementById('editSecReqTitle').value  = editSecReqTarget.title;
    document.getElementById('editSecReqDesc').value   = editSecReqTarget.description || '';
    // Set effort dropdown
    const effortSel = document.getElementById('editSecReqEffort');
    effortSel.innerHTML = IMPLEMENTATION_EFFORT.map(e =>
      `<option value="${e}"${editSecReqTarget.effort === e ? ' selected' : ''}>${e}</option>`
    ).join('');
    // Set status dropdown
    const statusSel = document.getElementById('editSecReqStatus');
    statusSel.innerHTML = REQUIREMENT_STATUS.map(s =>
      `<option value="${s}"${(editSecReqTarget.status || 'NA') === s ? ' selected' : ''}>${s}</option>`
    ).join('');
    bsEditSecReqModal.show();
  },
  deleteSecReq(idx) {
    const secReq = _currentSecReqs[idx];
    if (!secReq) return;
    // Remove all RequirementInstances referencing this SecurityRequirement
    for (const ia of interactions) {
      for (const l of STRIDE_LETTERS) {
        for (const ts of ia.attackDifficulty[l]) {
          ts.requirementInstances = ts.requirementInstances.filter(
            ri => ri.secRequirement !== secReq
          );
        }
      }
    }
    // Coloring results: recompute risks and refresh all visuals
    interactions.forEach((ia, i) => {
      ia.risks = computeAllRisks(ia);
      updateMessageTextColor(i);
    });
    interactions.forEach((_, i) => refreshAnnotationColors(i));
    updateCoverageScore();
    updateSecReqTable();
  },
  toggleSecReq(idx) {
    const secReq = _currentSecReqs[idx];
    if (!secReq) return;
    secReq.active = secReq.active === false ? true : false;
    interactions.forEach((ia, i) => {
      ia.risks = computeAllRisks(ia);
      updateMessageTextColor(i);
    });
    interactions.forEach((_, i) => refreshAnnotationColors(i));
    updateCoverageScore();
    updateSecReqTable();
  },
  sortSecReqTable(col) {
    if (tableSort.col === col) {
      tableSort.asc = !tableSort.asc;
    } else {
      tableSort = { col, asc: true };
    }
    updateSecReqTable();
  },
  showNewRequirementForm() {
    modalCtx.reqEditIndex = -1;
    modalCtx.page = 'newRequirement';
    renderStrideModalContent();
  },
  editRequirement(index) {
    modalCtx.reqEditIndex = index;
    modalCtx.page = 'newRequirement';
    renderStrideModalContent();
  },
  deleteRequirement(index) {
    const interaction  = interactions[modalCtx.interactionIndex];
    const techScenario = interaction.attackDifficulty[modalCtx.letter][modalCtx.editIndex];
    const secReq       = techScenario.requirementInstances[index].secRequirement;

    // secRequirement objects are unique by creation (live) or by deduplication on import (v0.66),
    // so identity is always the correct key — covers origin instances, propagated placeholders,
    // and imported instances regardless of whether the techScenario back-ref is present.
    for (const ia of interactions) {
      for (const l of STRIDE_LETTERS) {
        for (const ts of ia.attackDifficulty[l]) {
          for (let i = ts.requirementInstances.length - 1; i >= 0; i--) {
            if (ts.requirementInstances[i].secRequirement === secReq) {
              ts.requirementInstances.splice(i, 1);
            }
          }
        }
      }
    }

    renderStrideModalContent();
  },
};
window.app = app;

// ============================================================
// Export
// ============================================================

function exportData(filename) {
  // 'techScenario' is a transient back-reference (circular); strip it.
  // RequirementInstances with NA difficulties are placeholders — omit them too.
  const replacer = (key, value) => {
    if (key === 'techScenario') return undefined;
    if (key === 'requirementInstances' && Array.isArray(value)) {
      return value.filter(ri => ri.updatedTechDifficulty !== 'NA' && ri.updatedLogisticsDifficulty !== 'NA');
    }
    return value;
  };
  const payload = JSON.stringify({ sequenceDiagram: diagramMarkdown, interactions }, replacer, 2);
  const blob    = new Blob([payload], { type: 'application/json' });
  const url     = URL.createObjectURL(blob);
  const a       = document.createElement('a');
  a.href        = url;
  a.download    = `${filename}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================
// Utilities
// ============================================================

function escapeHtml(str) {
  return (str || '').replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
}

// ============================================================
// Risk Scoring Tables
// ============================================================

const RISK_CELL_BG = {
  NA:       '',
  None:     '#d1e7dd',
  Low:      '#fff3cd',
  Medium:   '#ffe5d0',
  High:     '#f8d7da',
  Critical: '#e2d9f3',
};

function buildRiskScoringHtml() {
  // ── BusinessRiskMatrix ────────────────────────────────────
  const bizHeaderCells = ['<th>Business Impact / Attack Difficulty</th>',
    ...ATTACK_DIFFICULTY.map(d => `<th class="text-center">${d}</th>`)].join('');

  const bizBodyRows = SEVERITY.map((impact, iIdx) =>
    '<tr><th>' + impact + '</th>' +
    ATTACK_DIFFICULTY.map((_, dIdx) => {
      const risk = BUSINESS_RISK_MATRIX[iIdx][dIdx];
      const bg   = RISK_CELL_BG[risk] ? ` style="background:${RISK_CELL_BG[risk]}"` : '';
      return `<td class="text-center fw-medium"${bg}>${risk}</td>`;
    }).join('') +
    '</tr>'
  ).join('');

  // ── DifficultyMatrix ──────────────────────────────────────
  const diffHeaderCells = ['<th>Technical / Logistics</th>',
    ...DIFFICULTY.map(d => `<th class="text-center">${d}</th>`)].join('');

  const diffBodyRows = DIFFICULTY.map((tech, tIdx) =>
    '<tr><th>' + tech + '</th>' +
    DIFFICULTY.map((_, lIdx) =>
      `<td class="text-center">${DIFFICULTY_MATRIX[tIdx][lIdx]}</td>`
    ).join('') +
    '</tr>'
  ).join('');

  return `
    <h6 class="fw-semibold mb-2">Business Risk Matrix</h6>
    <p class="text-muted small mb-1">Rows: business impact of the threat. Columns: combined attack difficulty.</p>
    <div class="table-responsive mb-4">
      <table class="table table-sm table-bordered mb-0">
        <thead class="table-light"><tr>${bizHeaderCells}</tr></thead>
        <tbody>${bizBodyRows}</tbody>
      </table>
    </div>
    <h6 class="fw-semibold mb-2">Difficulty Matrix</h6>
    <p class="text-muted small mb-1">Combines technical and logistics difficulty into a single attack difficulty.</p>
    <div class="table-responsive">
      <table class="table table-sm table-bordered mb-0">
        <thead class="table-light"><tr>${diffHeaderCells}</tr></thead>
        <tbody>${diffBodyRows}</tbody>
      </table>
    </div>
  `;
}

// ============================================================
// Crash Course Content  (source: crash_course.md)
// ============================================================

const CRASH_COURSE_MD = `### Goal: Identify security risks in the interactions between the components and prioritize what requires fixing

* Have a rather exhaustive methodology to list risks: STRIDE from Microsoft
* Compute a score for those risks
* Find security requirements (either a technical solution, a process or a doc) to reduce the severity of the most significant risks

### Customized STRIDE methodology

* 6 families of threats
  * Spoofing
  * Tampering
  * Repudiation
  * Information disclosure
  * Denial of service
  * Escalation of privilege

* Draw a high level diagram of the various components

* For every interaction between 2 components
  * Suppose a threat can be exploited (i.e. an attack exists)
  * Estimate the business impact of such attack (Low, Medium, High)
  * Estimate the complexity to execute such attack both from a technical and logistics point of view
  * Risk score computed according to tables in Risk Scoring

### What's next

* Build a list of security requirements prioritized by risk reduction vs implementation effort
* Restart the threat modeling loop to update risks when new components or features or added
`;

// ============================================================
// Initialisation
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'loose' });

  bsStrideModal = new bootstrap.Modal(document.getElementById('strideModal'), {
    backdrop: 'static',
    keyboard: false,
  });
  bsImportModal       = new bootstrap.Modal(document.getElementById('importModal'));
  bsExportModal       = new bootstrap.Modal(document.getElementById('exportModal'));
  bsCrashCourseModal  = new bootstrap.Modal(document.getElementById('crashCourseModal'));
  bsRiskScoringModal  = new bootstrap.Modal(document.getElementById('riskScoringModal'));
  bsEditSecReqModal   = new bootstrap.Modal(document.getElementById('editSecReqModal'));

  // ── Edit SecurityRequirement (from table) ──────────────────
  document.getElementById('editSecReqSaveBtn').addEventListener('click', () => {
    if (!editSecReqTarget) return;
    const titleInput = document.getElementById('editSecReqTitle');
    const title = titleInput.value.trim();
    if (!title) { titleInput.classList.add('is-invalid'); return; }
    // Mutate in place so all RequirementInstance references remain valid
    editSecReqTarget.title       = title;
    editSecReqTarget.description = document.getElementById('editSecReqDesc').value.trim();
    editSecReqTarget.effort      = document.getElementById('editSecReqEffort').value;
    editSecReqTarget.status      = document.getElementById('editSecReqStatus').value;
    editSecReqTarget = null;
    bsEditSecReqModal.hide();
    interactions.forEach((_, i) => refreshAnnotationColors(i));
    updateSecReqTable();
  });

  // ── Import ─────────────────────────────────────────────────
  document.getElementById('importBtn').addEventListener('click', () => {
    // Clear any previous error and restore the current markdown for editing
    document.getElementById('importError').style.display = 'none';
    document.getElementById('diagramInput').value = diagramMarkdown;
    bsImportModal.show();
  });

  document.getElementById('importConfirmBtn').addEventListener('click', async () => {
    const markdown = document.getElementById('diagramInput').value.trim();
    if (!markdown) return;

    const confirmBtn = document.getElementById('importConfirmBtn');
    const errorEl   = document.getElementById('importError');

    // Hide any previous error
    errorEl.style.display = 'none';

    // Disable button while rendering to prevent double-click
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Rendering…';

    // Capture the ID before the try so finally can always clean up the
    // temporary DOM elements mermaid leaves behind on parse errors.
    renderCount++;
    const renderId = `litetm-diagram-${renderCount}`;

    try {
      // Attempt to render BEFORE closing the modal.
      // Spec: "If there is a syntax error, the modal cannot be closed."
      const { svg } = await mermaid.render(renderId, markdown);

      // Render succeeded — update state, close modal, show diagram
      diagramMarkdown = markdown;
      interactions    = parseSequenceDiagram(markdown);

      bsImportModal.hide();
      displaySvg(svg);

      // Two rAF ticks so layout is stable before we measure positions
      await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
      injectStrideOverlays();
      colorAllMessageTexts();
      updateCoverageScore();
      updateSecReqTable();

    } catch (err) {
      // Render failed — keep modal open and show the error.
      // On a parse error mermaid throws without cleaning up the temporary
      // `<div id="d${renderId}">` it appended to document.body, leaving the
      // bomb SVG visible on the page.  Remove both possible remnants here.
      // (On success mermaid removes them itself, so this only runs on error.)
      document.getElementById(`d${renderId}`)?.remove();
      document.getElementById(renderId)?.remove();

      const msg = String(err.message || err).replace(/^(Error:\s*)+/i, '');
      errorEl.textContent = '⚠ Syntax error: ' + msg;
      errorEl.style.display = 'block';
    } finally {
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Render Diagram';
    }
  });

  // ── Import existing JSON ────────────────────────────────────
  document.getElementById('importJsonBtn').addEventListener('click', () => {
    document.getElementById('importJsonInput').click();
  });

  document.getElementById('importJsonInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    // Reset immediately so the same file can be re-selected later
    e.target.value = '';

    let data;
    try {
      data = JSON.parse(await file.text());
    } catch {
      alert('Could not parse file — not valid JSON.');
      return;
    }

    if (typeof data.sequenceDiagram !== 'string' || !Array.isArray(data.interactions)) {
      alert('Invalid format: expected sequenceDiagram (string) and interactions (array).');
      return;
    }

    renderCount++;
    const renderId = `litetm-diagram-${renderCount}`;

    try {
      const { svg } = await mermaid.render(renderId, data.sequenceDiagram);

      diagramMarkdown = data.sequenceDiagram;
      interactions    = data.interactions;

      // Ensure every TechnicalScenario has requirementInstances (added in v0.50)
      for (const ia of interactions) {
        for (const l of STRIDE_LETTERS) {
          for (const ts of ia.attackDifficulty[l]) {
            if (!ts.requirementInstances) ts.requirementInstances = [];
          }
        }
      }

      // Deduplicate: secRequirements with the same title+source+destination share one object,
      // so identity checks (seen.has, ri.secRequirement === secReq) work correctly after import.
      const reqMap = new Map();
      for (const ia of interactions) {
        for (const l of STRIDE_LETTERS) {
          for (const ts of ia.attackDifficulty[l]) {
            for (const ri of ts.requirementInstances) {
              const key = `${ri.secRequirement.title}||${ri.secRequirement.source}||${ri.secRequirement.destination}`;
              if (!reqMap.has(key)) {
                if (ri.secRequirement.active === undefined) ri.secRequirement.active = true;
                reqMap.set(key, ri.secRequirement);
              } else {
                ri.secRequirement = reqMap.get(key);
              }
            }
          }
        }
      }

      // Re-propagate each secRequirement to all matching TechnicalScenarios
      // (placeholder instances were stripped on export).
      for (let i = 0; i < interactions.length; i++) syncAllForInteraction(i);

      displaySvg(svg);
      await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
      injectStrideOverlays();
      colorAllMessageTexts();
      updateCoverageScore();
      updateSecReqTable();

    } catch (err) {
      document.getElementById(`d${renderId}`)?.remove();
      document.getElementById(renderId)?.remove();
      alert('Could not render the diagram from the JSON: ' + (err.message || err));
    }
  });

  // ── Export ──────────────────────────────────────────────────
  document.getElementById('exportBtn').addEventListener('click', () => {
    bsExportModal.show();
  });

  document.getElementById('exportConfirmBtn').addEventListener('click', () => {
    const filename = document.getElementById('exportFilename').value.trim() || 'threat-model';
    exportData(filename);
    bsExportModal.hide();
  });

  // ── Risk Scoring ───────────────────────────────────────────
  document.getElementById('riskScoringBtn').addEventListener('click', () => {
    document.getElementById('riskScoringBody').innerHTML = buildRiskScoringHtml();
    bsRiskScoringModal.show();
  });

  // ── Crash Course ───────────────────────────────────────────
  document.getElementById('crashCourseBtn').addEventListener('click', () => {
    let html = marked.parse(CRASH_COURSE_MD)
      .replace(/<table>/g, '<table class="table table-sm table-bordered">');

    // Single-pass: add help icons next to STRIDE names; HTML tags are skipped
    // so attribute values (e.g. data-bs-title) are never mutated.
    html = html.replace(STRIDE_MENTION_RE, m =>
      m.startsWith('<') ? m : `${m} ${helpIconHtml(letterForMention(m))}`
    );

    const body = document.getElementById('crashCourseBody');
    body.innerHTML = html;
    initTooltips(body);
    bsCrashCourseModal.show();
  });

  // ── STRIDE modal X button ───────────────────────────────────
  // No data-bs-dismiss on this button — we intercept the click manually so
  // we can (a) compute risks before hiding, and (b) navigate sub-pages back
  // to main instead of closing outright.
  document.getElementById('strideModalCloseBtn').addEventListener('click', () => {
    if (modalCtx.page === 'main') {
      closeStrideModal();
    } else if (modalCtx.page === 'newRequirement') {
      modalCtx.page = 'newTech';
      modalCtx.reqEditIndex = -1;
      renderStrideModalContent();
    } else {
      // On sub-pages X goes back to the main list, not out of the modal
      modalCtx.page = 'main';
      renderStrideModalContent();
    }
  });
});
