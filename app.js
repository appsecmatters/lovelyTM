// ============================================================
// LiteTM — Lightweight Threat Modeling Tool  (v0.20)
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

/** Returns an HTML help-icon span with a Bootstrap tooltip containing the definition. */
function helpIconHtml(letter) {
  return `<span class="help-icon" data-bs-toggle="tooltip" data-bs-placement="auto" data-bs-title="${escapeHtml(STRIDE_DEFINITIONS[letter])}">ⓘ</span>`;
}

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
};

// Bootstrap modal instances — initialised in DOMContentLoaded
let bsStrideModal;
let bsImportModal;
let bsExportModal;
let bsCrashCourseModal;

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

  const color = RISK_COLORS[getInteractionMaxRisk(interactions[interactionIndex])];
  el.style.fill = color ?? '';   // null (NA) → clear → browser default (black)
}

/** Tint every message-text label to match the current max-risk of its interaction. */
function colorAllMessageTexts() {
  interactions.forEach((_, idx) => updateMessageTextColor(idx));
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
  // Recompute risks, refresh STRIDE letter badges, and tint the message text
  const interaction = interactions[modalCtx.interactionIndex];
  interaction.risks = computeAllRisks(interaction);
  refreshAnnotationColors(modalCtx.interactionIndex);
  updateMessageTextColor(modalCtx.interactionIndex);
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
      <button class="btn btn-sm btn-outline-success mt-2 mb-4"
              onclick="app.showNewBusinessForm()">+ Add Business Scenario</button>

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
      <button class="btn btn-sm btn-outline-success mt-2"
              onclick="app.showNewTechForm()">+ Add Attack Scenario</button>

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

    titleEl.textContent = isEdit ? 'Edit Business Impact Scenario' : 'Add Business Impact Scenario';

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

  // ── TechnicalScenario form (create or edit) ────────────────
  } else if (page === 'newTech') {
    const isEdit   = editIndex >= 0;
    const existing = isEdit ? interaction.attackDifficulty[letter][editIndex] : null;

    titleEl.textContent = isEdit ? 'Edit Attack Scenario' : 'Add Attack Scenario';

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

  const scenario = {
    title,
    description:          document.getElementById('techDescription').value.trim(),
    technicalDifficulty:  document.getElementById('techDiff').value,
    logisticsDifficulty:  document.getElementById('logsDiff').value,
  };

  const list = interactions[modalCtx.interactionIndex].attackDifficulty[modalCtx.letter];
  if (modalCtx.editIndex >= 0) {
    list[modalCtx.editIndex] = scenario;   // update existing
  } else {
    list.push(scenario);                   // add new
  }

  modalCtx.page = 'main';
  modalCtx.editIndex = -1;
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
};
window.app = app;

// ============================================================
// Export
// ============================================================

function exportData(filename) {
  const payload = JSON.stringify({ sequenceDiagram: diagramMarkdown, interactions }, null, 2);
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
  * Risk score computed according to tables in \`SPECS.md\`

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

      displaySvg(svg);
      await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
      injectStrideOverlays();
      colorAllMessageTexts();

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
    } else {
      // On sub-pages X goes back to the list, not out of the modal
      modalCtx.page = 'main';
      renderStrideModalContent();
    }
  });
});
