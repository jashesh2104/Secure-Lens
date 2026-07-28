/*
 * generate_ppt.js
 * Generates: SecureLens_Review1.pptx
 * BCSE 497J Project-I, Review-1
 *
 * Professional cybersecurity aesthetic:
 *   - dark navy background (0F1B2D)
 *   - cyan accents (00D4FF)
 *   - white body text
 * Architecture drawn purely from pptxgenjs shapes (no images).
 */

const PptxGenJS = require("pptxgenjs");

const pres = new PptxGenJS();
pres.layout = "LAYOUT_16x9"; // must be set before adding slides
pres.author = "SecureLens Team";
pres.company = "Vellore Institute of Technology";
pres.title = "SecureLens Review-1";

// ---- Palette (no '#' anywhere) --------------------------------------------
const NAVY = "0F1B2D";
const NAVY_2 = "16263D";
const PANEL = "1C2E48";
const CYAN = "00D4FF";
const CYAN_DK = "0A8FB0";
const WHITE = "FFFFFF";
const SLATE = "B8C6D9";
const GREEN = "2ECC71";
const AMBER = "F5A623";
const VIOLET = "8E7BEF";

const FONT = "Calibri";
const SW = 10; // slide width  (inches, 16x9)
const SH = 5.625; // slide height (inches, 16x9)

let slideNo = 0;

// Apply the navy background + top section title to a content slide.
function contentSlide(titleText) {
  slideNo += 1;
  const slide = pres.addSlide();
  slide.background = { color: NAVY };

  slide.addText(titleText, {
    x: 0.45,
    y: 0.28,
    w: 9.1,
    h: 0.6,
    fontFace: FONT,
    fontSize: 26,
    bold: true,
    color: CYAN,
    align: "left",
    margin: 0,
  });

  // slide number bottom-right
  slide.addText(String(slideNo), {
    x: 9.2,
    y: 5.2,
    w: 0.6,
    h: 0.3,
    fontFace: FONT,
    fontSize: 11,
    color: SLATE,
    align: "right",
    margin: 0,
  });
  return slide;
}

// Helper: bulleted text block from an array of strings.
function bullets(items, opts = {}) {
  return items.map((t) => ({
    text: t,
    options: {
      bullet: { indent: 18 },
      color: opts.color || WHITE,
      fontSize: opts.fontSize || 15,
      fontFace: FONT,
      paraSpaceAfter: opts.spaceAfter != null ? opts.spaceAfter : 8,
      breakLine: true,
    },
  }));
}

/* =====================================================================
 * SLIDE 1 — TITLE
 * ===================================================================== */
(function titleSlide() {
  const slide = pres.addSlide();
  slide.background = { color: NAVY };

  // subtle top panel band for the project code
  slide.addShape(pres.ShapeType.rect, {
    x: 0,
    y: 0,
    w: SW,
    h: 0.5,
    fill: { color: NAVY_2 },
    line: { color: NAVY_2 },
  });
  slide.addText("BCSE 497J  •  Project-I  •  Review-1", {
    x: 0,
    y: 0.05,
    w: SW,
    h: 0.4,
    fontFace: FONT,
    fontSize: 13,
    color: CYAN,
    align: "center",
    margin: 0,
  });

  slide.addText("SecureLens", {
    x: 0.5,
    y: 1.15,
    w: 9,
    h: 0.9,
    fontFace: FONT,
    fontSize: 48,
    bold: true,
    color: WHITE,
    align: "center",
    margin: 0,
  });
  slide.addText("AI-Augmented DevSecOps Vulnerability Triage Platform", {
    x: 0.5,
    y: 2.05,
    w: 9,
    h: 0.5,
    fontFace: FONT,
    fontSize: 20,
    color: CYAN,
    align: "center",
    margin: 0,
  });

  // students row
  slide.addText(
    [
      {
        text: "Neel Lokhandwala (23BCE0600)      Khushi Singh (23BCE0266)      Jashesh Patel (23BCE0552)",
        options: { fontSize: 15, color: WHITE, breakLine: true, fontFace: FONT },
      },
    ],
    { x: 0.5, y: 2.95, w: 9, h: 0.4, align: "center", margin: 0 }
  );

  slide.addText(
    [
      { text: "Guide: ", options: { color: SLATE, fontSize: 14, fontFace: FONT } },
      { text: "Ms. Maheswari B", options: { color: WHITE, fontSize: 14, bold: true, fontFace: FONT } },
    ],
    { x: 0.5, y: 3.5, w: 9, h: 0.35, align: "center", margin: 0 }
  );

  slide.addText("School of Computer Science and Engineering", {
    x: 0.5,
    y: 3.95,
    w: 9,
    h: 0.35,
    fontFace: FONT,
    fontSize: 14,
    color: WHITE,
    align: "center",
    margin: 0,
  });
  slide.addText("Vellore Institute of Technology, Vellore", {
    x: 0.5,
    y: 4.3,
    w: 9,
    h: 0.35,
    fontFace: FONT,
    fontSize: 14,
    color: SLATE,
    align: "center",
    margin: 0,
  });
})();

/* =====================================================================
 * SLIDE 2 — INTRODUCTION: BACKGROUND & PROBLEM
 * ===================================================================== */
(function () {
  const slide = contentSlide("Introduction — Background & Problem");
  slide.addText(
    bullets([
      "Software teams lose hours manually reviewing scanner alerts before any real fix begins.",
      "Tools like SonarQube and Snyk detect vulnerabilities but do not explain why they matter.",
      "Developers who introduced the bug often lack the context to judge true severity.",
      "Alert fatigue causes genuine, exploitable threats to be overlooked and dismissed.",
      "No self-hostable tool connects detection \u2192 explanation \u2192 prioritization in one pipeline.",
    ]),
    { x: 0.6, y: 1.15, w: 8.8, h: 3.8, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDE 3 — INTRODUCTION: CURRENT CHALLENGES & NEED
 * ===================================================================== */
(function () {
  const slide = contentSlide("Introduction — Current Challenges & Need");
  slide.addText(
    bullets([
      "SAST/DAST tools emit raw finding lists with no exploit context or remediation guidance.",
      "Multiple scanners (SonarQube, Gitleaks) produce incompatible output formats and severities.",
      "LLMs used alone hallucinate security advice, inventing CVEs and unsupported facts.",
      "RAG over curated CVE / OWASP / CWE data grounds the model and solves the hallucination problem.",
      "Need: a unified, explainable, self-hosted DevSecOps triage pipeline for engineering teams.",
    ]),
    { x: 0.6, y: 1.15, w: 8.8, h: 3.8, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDE 4 — OBJECTIVES
 * ===================================================================== */
(function () {
  const slide = contentSlide("Objectives");
  const objs = [
    "Integrate SonarQube SAST and Gitleaks secret detection into a unified FastAPI backend with a normalised finding schema.",
    "Build a RAG pipeline over an OWASP Top 10 and CWE Top 25 knowledge base using ChromaDB to ground LLM security explanations.",
    "Deploy a Groq-powered LLM triage agent that re-ranks severity and generates plain-English exploit scenarios and fix suggestions.",
    "Develop a React dashboard with real-time scan-status polling and JWT-authenticated access to triage results.",
    "Implement GitHub Actions CI/CD that auto-posts AI-generated vulnerability summaries to PRs and blocks merges on critical findings.",
  ];
  slide.addText(
    objs.map((t, i) => ({
      text: `${i + 1}.  ${t}`,
      options: {
        color: WHITE,
        fontSize: 14,
        fontFace: FONT,
        paraSpaceAfter: 12,
        breakLine: true,
      },
    })),
    { x: 0.6, y: 1.1, w: 8.8, h: 4.0, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDES 5-9 — LITERATURE SURVEY (15 papers, 5 per student)
 * ===================================================================== */
const litGroups = [
  {
    student: "Reviewer 1 — Neel Lokhandwala (23BCE0600)",
    theme: "LLM & AI for Vulnerability Detection",
    papers: [
      {
        t: "LLbezpeky: Leveraging LLMs for Vulnerability Detection",
        a: "Mathews, Brus, Aafer, Nagappan, McIntosh",
        y: "2024",
        pub: "arXiv / Univ. of Waterloo",
        m: "Prompt-driven LLM analysis over Android app code with iterative context building.",
        k: "LLMs flag injection and access-control flaws missed by signature-based scanners.",
        l: "Sensitive to prompt design; no retrieval grounding, so results vary run-to-run.",
      },
      {
        t: "Representation Matters: Program Representations for LLM Vulnerability Reasoning (RepBench)",
        a: "Stoltman, Tang, Cai",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Benchmarks raw source vs AST/CFG/PDG graph inputs on PrimeVul C/C++ testcases.",
        k: "AST+PDG reaches 83.2% accuracy vs 53.5% for raw source; graphs reduce prompt size.",
        l: "Static-analysis pre-processing adds pipeline complexity; limited to five CWE classes.",
      },
      {
        t: "Revelio: Cost-Efficient Agentic Memory-Safety Detection for Repository-Scale Codebases",
        a: "Hou, Wang, Momeu, Sen, Song, Wagner et al.",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Agentic loop generates executable Proof-of-Vulnerability checked by a sanitizer.",
        k: "Found 19 previously unknown memory-safety bugs across long-fuzzed projects at low cost.",
        l: "Scoped to memory safety; depends on reproducible builds and sanitizer coverage.",
      },
      {
        t: "Evaluating LLMs for Real-World Web Vulnerability Detection",
        a: "Neef, Jungnickel, Buchholz et al.",
        y: "2026",
        pub: "ARES 2026 Workshop",
        m: "Benchmarks frontier and open-weight models on WordPress plugin SQLi/XSS/RCE.",
        k: "Scoped prompts beat open-ended; best model reached 63% web-vuln detection rate.",
        l: "No model was fully consistent across runs; some as low as 50% reproducibility.",
      },
      {
        t: "DREA: Decoupled Reasoning & Exploration Agents for Repository-Level Detection",
        a: "Sun, Meng",
        y: "2026",
        pub: "Internetware 2026",
        m: "Planner LLM forms hypotheses; lightweight explorer retrieves repo-level context on demand.",
        k: "Raises pair-correctness from 19-26% to 30-42% while cutting API cost 16-48x.",
        l: "26-55% of true positives are backed by flawed rationales; reasoning quality lags.",
      },
    ],
  },
  {
    student: "Reviewer 2 — Khushi Singh (23BCE0266)",
    theme: "Retrieval-Augmented Generation for Cybersecurity",
    papers: [
      {
        t: "Advancing TTP Analysis with LLMs and Retrieval-Augmented Generation",
        a: "Fayyazi, Taghdimi, Yang",
        y: "2024",
        pub: "arXiv (cs.CR)",
        m: "RAG over MITRE ATT&CK to interpret adversary tactics, techniques and procedures.",
        k: "Retrieval grounding yields more accurate, cited TTP interpretations than raw LLMs.",
        l: "Quality bounded by knowledge-base coverage and retriever recall.",
      },
      {
        t: "KASS: Knowledge-Augmented Attack Synthesis & Simulation for Smart Contracts",
        a: "Zhang, Sun, Zhang, Liu et al.",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Retrieval-augmented planning over audit knowledge to build executable exploits.",
        k: "Generates working exploits for 94.2% of contracts; filters static-analysis false positives.",
        l: "Evaluated on curated SmartBugs set; exploit validity needs formal test binding.",
      },
      {
        t: "VeriChat: Agentic Conversational Assistant for Hardware Security Verification",
        a: "Saha, Hasan, Tarek, Tehranipoor, Farahmandi",
        y: "2026",
        pub: "IEEE COINS 2026",
        m: "Retrieval-augmented multi-agent workflow integrating open-source EDA tooling.",
        k: "Faithfulness 87.7%, outperforming proprietary chatbots; proves a key-leakage Trojan.",
        l: "Domain-specific to RTL/hardware; relies on curated verification corpus.",
      },
      {
        t: "Multi-Agent HybridRAG for Automated IT-Grundschutz Security Audits",
        a: "Muth, Margraf",
        y: "2026",
        pub: "IEEE SysCon 2026",
        m: "Hybrid RAG + knowledge graph with a hypothesis-verification loop to cut hallucinations.",
        k: "Strong on semantic extraction tasks, reducing manual certification effort.",
        l: "Struggles on deterministic logical-reasoning phases required by strict compliance.",
      },
      {
        t: "Knowledge-Base Poisoning Attacks & Defense for Policy-Aware LLM-RAG",
        a: "Solanki, Praharaj, Gupta, Gupta",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Studies retrieval-poisoning of a RAG knowledge base; proposes CLD-KB anomaly defense.",
        k: "A single injected rule corrupts 85% of LLM context; defense adds only ~7ms overhead.",
        l: "Shows RAG knowledge bases must be integrity-protected and access-controlled.",
      },
    ],
  },
  {
    student: "Reviewer 3 — Jashesh Patel (23BCE0552)",
    theme: "DevSecOps Automation & LLM Code-Security Review",
    papers: [
      {
        t: "KernelGPT: Enhanced Kernel Fuzzing via Large Language Models",
        a: "Yang, Zhao, Zhang",
        y: "2025",
        pub: "ASPLOS 2025",
        m: "LLM synthesises syscall specifications to drive automated kernel fuzzing.",
        k: "Discovered real, previously unknown Linux kernel bugs via LLM-generated specs.",
        l: "Requires validation harness; scope limited to syscall-reachable code paths.",
      },
      {
        t: "LeanGuard: Neuro-Symbolic Reasoning for Vulnerability Detection",
        a: "Zhao, Chen, Lu, Yang, Cheng, Wang",
        y: "2026",
        pub: "arXiv (cs.SE)",
        m: "LLM filters AST facts; Lean 4 proof kernel discharges memory-safety obligations.",
        k: "Separating interpretation from proof curbs the 'plausible but wrong' LLM verdicts.",
        l: "Partial models leave obligations open; needs richer inter-procedural context.",
      },
      {
        t: "Words Speak Louder Than Code: Cognitive Heuristics in LLM Vuln Detection",
        a: "Shahriar, Cai, Benkraouda, Wang, Celik",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Holds code fixed, varies surrounding context to trigger framing/anchoring/halo bias.",
        k: "All 8 models are biased; framing shifts verdicts 33%; a black-box attack hides 97%.",
        l: "Reveals context-injection risk; triage prompts must be bias-hardened.",
      },
      {
        t: "Knowledge-Guided Vulnerability Detection with LLM & Code Slicing (Ethereum NFT)",
        a: "Yang, Wei, Li",
        y: "2026",
        pub: "arXiv (cs.CR)",
        m: "Vulnerability-focused code slicing + ERC-721 knowledge base + constrained LLM schema.",
        k: "Knowledge base lifted positive-label rate from 73.8% to 97.1% on 450 contracts.",
        l: "Domain-bound to NFT contracts; regex candidate selection can miss novel patterns.",
      },
      {
        t: "Beyond Refusal: Aligned vs Abliterated LLMs for Vulnerability Analysis",
        a: "Li, Qiu, Peng, Fan, Fu, Ding, Feng",
        y: "2026",
        pub: "arXiv (cs.SE)",
        m: "Same-lineage study of safety state across detection, CWE attribution, patch validation.",
        k: "Safety alignment can suppress legitimate defensive security utility for developers.",
        l: "Trade-off between safety and usefulness; motivates security-aware evaluation.",
      },
    ],
  },
];

litGroups.forEach((group) => {
  const slide = contentSlide("Literature Survey");
  // sub-header: student + theme
  slide.addText(
    [
      { text: group.student, options: { color: WHITE, fontSize: 13, bold: true, fontFace: FONT } },
      { text: "   |   " + group.theme, options: { color: CYAN, fontSize: 12, italic: true, fontFace: FONT } },
    ],
    { x: 0.45, y: 0.92, w: 9.1, h: 0.32, margin: 0 }
  );

  // Build a table: header + 5 paper rows
  const header = ["Paper / Authors / Year / Publisher", "Methodology", "Key Findings", "Limitations"].map((h) => ({
    text: h,
    options: {
      fill: { color: CYAN_DK },
      color: WHITE,
      bold: true,
      fontSize: 10,
      fontFace: FONT,
      valign: "middle",
      align: "left",
    },
  }));

  const rows = [header];
  group.papers.forEach((p, idx) => {
    const zebra = idx % 2 === 0 ? PANEL : NAVY_2;
    rows.push([
      {
        text: `${p.t}\n${p.a} (${p.y}) — ${p.pub}`,
        options: { fill: { color: zebra }, color: WHITE, fontSize: 8.5, fontFace: FONT, valign: "top" },
      },
      { text: p.m, options: { fill: { color: zebra }, color: SLATE, fontSize: 8.5, fontFace: FONT, valign: "top" } },
      { text: p.k, options: { fill: { color: zebra }, color: SLATE, fontSize: 8.5, fontFace: FONT, valign: "top" } },
      { text: p.l, options: { fill: { color: zebra }, color: SLATE, fontSize: 8.5, fontFace: FONT, valign: "top" } },
    ]);
  });

  slide.addTable(rows, {
    x: 0.4,
    y: 1.3,
    w: 9.2,
    colW: [2.9, 2.1, 2.1, 2.1],
    rowH: [0.3, 0.72, 0.72, 0.72, 0.72, 0.72],
    border: { type: "solid", color: NAVY, pt: 1 },
    align: "left",
    valign: "top",
    margin: 3,
  });
});

/* =====================================================================
 * SLIDE 10 — RESEARCH GAP
 * ===================================================================== */
(function () {
  const slide = contentSlide("Research Gap");
  slide.addText(
    bullets([
      "Existing tools detect vulnerabilities but do not explain or teach why they are dangerous.",
      "No open-source, RAG-grounded security explainer bridges detection and developer understanding.",
      "LLMs without retrieval hallucinate CVE details, severities, and remediation steps.",
      "Open tools lack a unified normalisation layer across multiple SAST/secret scanners.",
      "Gap: a self-hosted, RAG-grounded, explanation-first vulnerability triage platform.",
    ]),
    { x: 0.6, y: 1.15, w: 8.8, h: 3.8, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDE 11 — PROPOSED SYSTEM: SOLUTION OVERVIEW
 * ===================================================================== */
(function () {
  const slide = contentSlide("Proposed System — Solution Overview");
  slide.addText(
    [
      { text: "What SecureLens does differently", options: { color: CYAN, fontSize: 15, bold: true, fontFace: FONT, breakLine: true, paraSpaceAfter: 8 } },
      ...bullets([
        "Novel contribution: RAG retrieval over OWASP/CWE runs BEFORE the LLM call — not raw LLM prompting.",
        "Hybrid search combines dense embeddings with CWE metadata filters for precise grounding.",
        "The LLM re-ranks severity and cites the exact knowledge-base documents it used.",
      ]),
      { text: "Expected advantages", options: { color: CYAN, fontSize: 15, bold: true, fontFace: FONT, breakLine: true, paraSpaceBefore: 6, paraSpaceAfter: 8 } },
      ...bullets([
        "Grounded, citable explanations instead of hallucinated security advice.",
        "Reduced false-positive triage time and lower alert fatigue for developers.",
        "Developer security education is built directly into the CI/CD workflow.",
      ]),
    ],
    { x: 0.6, y: 1.1, w: 8.8, h: 4.0, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDE 12 — PROPOSED SYSTEM: TECHNOLOGIES
 * ===================================================================== */
(function () {
  const slide = contentSlide("Proposed System — Technologies");
  const groupsTech = [
    ["Backend", "FastAPI, SQLAlchemy, SQLite \u2192 PostgreSQL, slowapi rate-limiting, JWT auth"],
    ["RAG & LLM", "LangChain (LCEL), ChromaDB vector store, Groq LLM (llama-3.1-8b-instant), nomic-embed-text"],
    ["Scanners", "SonarQube Community Build (SAST), Gitleaks (secret detection)"],
    ["Frontend", "React + Vite + Tailwind CSS, TanStack Query polling"],
    ["CI/CD & Cloud", "GitHub Actions, PR comment bot + merge gate, AWS EC2 deployment"],
  ];
  const rows = groupsTech.map((g, i) => [
    { text: g[0], options: { fill: { color: CYAN_DK }, color: WHITE, bold: true, fontSize: 13, fontFace: FONT, valign: "middle" } },
    { text: g[1], options: { fill: { color: i % 2 === 0 ? PANEL : NAVY_2 }, color: WHITE, fontSize: 13, fontFace: FONT, valign: "middle" } },
  ]);
  slide.addTable(rows, {
    x: 0.6,
    y: 1.25,
    w: 8.8,
    colW: [2.3, 6.5],
    rowH: [0.66, 0.66, 0.66, 0.66, 0.66],
    border: { type: "solid", color: NAVY, pt: 1 },
    valign: "middle",
    margin: 5,
  });
})();

/* =====================================================================
 * SLIDE 13 — SYSTEM ARCHITECTURE (shapes only)
 * ===================================================================== */
(function () {
  const slide = contentSlide("System Architecture");

  // Reusable box drawer
  function box(x, y, w, h, label, fillColor, textColor) {
    slide.addShape(pres.ShapeType.roundRect, {
      x,
      y,
      w,
      h,
      rectRadius: 0.06,
      fill: { color: fillColor },
      line: { color: CYAN, width: 1 },
    });
    slide.addText(label, {
      x,
      y,
      w,
      h,
      fontFace: FONT,
      fontSize: 9,
      color: textColor || WHITE,
      align: "center",
      valign: "middle",
      bold: true,
      margin: 0,
    });
  }

  function arrow(x1, y1, x2, y2) {
    slide.addShape(pres.ShapeType.line, {
      x: x1,
      y: y1,
      w: x2 - x1,
      h: y2 - y1,
      line: { color: CYAN, width: 1.5, endArrowType: "triangle" },
    });
  }

  const BW = 1.85;
  const BH = 0.55;

  // Row 1 (top): source + CI
  box(0.35, 1.15, BW, BH, "GitHub Push / PR", VIOLET, NAVY);
  box(2.55, 1.15, BW, BH, "GitHub Actions CI", VIOLET, NAVY);
  box(4.75, 1.15, BW, BH, "FastAPI Backend :8000", CYAN_DK);

  arrow(2.2, 1.42, 2.55, 1.42); // push -> CI
  arrow(4.4, 1.42, 4.75, 1.42); // CI -> backend

  // Row 2: scanners
  box(2.55, 2.1, BW, BH, "SonarQube Runner", PANEL);
  box(4.75, 2.1, BW, BH, "SonarQube :9000", NAVY_2);
  box(0.35, 2.1, BW, BH, "Gitleaks Runner", PANEL);

  arrow(5.35, 1.7, 5.35, 2.1); // backend -> sonar runner? backend down
  arrow(3.475, 2.1, 3.475, 1.7); // sonar runner -> up to backend region (visual link)
  arrow(4.4, 2.375, 4.75, 2.375); // sonar runner -> sonarqube server
  // backend -> gitleaks
  arrow(4.75, 1.55, 1.3, 2.1);

  // Row 3: normalizer + finding schema
  box(2.55, 3.05, BW, BH, "Normalizer", PANEL);
  box(4.75, 3.05, BW, BH, "Finding Schema", CYAN_DK);
  arrow(3.475, 2.65, 3.475, 3.05); // sonar runner -> normalizer
  arrow(1.3, 2.65, 2.7, 3.05); // gitleaks -> normalizer
  arrow(4.4, 3.325, 4.75, 3.325); // normalizer -> finding schema

  // Row 4: RAG + KB + Triage + Groq
  box(0.35, 4.0, BW, BH, "RAG Engine", PANEL);
  box(2.55, 4.0, BW, BH, "ChromaDB + OWASP/CWE KB", NAVY_2);
  box(4.75, 4.0, BW, BH, "Triage Agent", PANEL);
  box(6.95, 4.0, BW, BH, "Groq LLM", GREEN, NAVY);

  arrow(4.75, 3.6, 1.3, 4.0); // finding schema -> RAG engine
  arrow(2.2, 4.275, 2.55, 4.275); // RAG -> ChromaDB
  arrow(1.3, 4.0, 4.9, 3.6); // RAG -> triage (grounded context) upward-ish
  arrow(4.4, 4.275, 4.75, 4.275); // finding-region -> triage (visual)
  arrow(6.6, 4.275, 6.95, 4.275); // triage -> groq

  // Right column outputs: DB, dashboard, PR bot
  box(6.95, 1.15, BW, BH, "React Dashboard :5173", CYAN_DK);
  box(6.95, 2.1, BW, BH, "PostgreSQL / SQLite", NAVY_2);
  box(6.95, 3.05, BW, BH, "PR Comment Bot", AMBER, NAVY);

  arrow(5.7, 4.0, 7.4, 2.65); // triage -> postgres
  arrow(7.875, 2.1, 7.875, 1.7); // postgres -> dashboard
  arrow(5.7, 4.0, 7.6, 3.6); // triage -> PR bot

  // Legend
  slide.addText(
    [
      { text: "\u25A0 ", options: { color: VIOLET, fontSize: 9, fontFace: FONT } },
      { text: "Source/CI   ", options: { color: SLATE, fontSize: 9, fontFace: FONT } },
      { text: "\u25A0 ", options: { color: CYAN_DK, fontSize: 9, fontFace: FONT } },
      { text: "Core service   ", options: { color: SLATE, fontSize: 9, fontFace: FONT } },
      { text: "\u25A0 ", options: { color: GREEN, fontSize: 9, fontFace: FONT } },
      { text: "LLM   ", options: { color: SLATE, fontSize: 9, fontFace: FONT } },
      { text: "\u25A0 ", options: { color: AMBER, fontSize: 9, fontFace: FONT } },
      { text: "Output", options: { color: SLATE, fontSize: 9, fontFace: FONT } },
    ],
    { x: 0.35, y: 4.75, w: 9, h: 0.3, align: "left", margin: 0 }
  );
})();

/* =====================================================================
 * SLIDE 14 — METHODOLOGY
 * ===================================================================== */
(function () {
  const slide = contentSlide("Methodology");
  const steps = [
    ["Data Collection", "OWASP Top 10 + CWE Top 25 markdown corpus as the grounding knowledge base."],
    ["Preprocessing", "Chunk docs (~800 chars, 120 overlap); embed with nomic-embed-text via Ollama."],
    ["Feature Extraction", "Attach CWE-ID and severity metadata as filters applied during retrieval."],
    ["Model", "LangChain LCEL chain: ChromaDB retrieval \u2192 Groq LLM with structured output."],
    ["RAG Pipeline", "Hybrid dense + metadata search returning the top-k most relevant chunks."],
    ["Output", "TriageResult schema: re-ranked severity, explanation, exploit, fix, references."],
    ["Evaluation", "Manual spot-check of triage accuracy on OWASP Juice Shop findings."],
    ["Integration", "GitHub Actions workflow posts PR comment and enforces the critical merge gate."],
  ];
  const rows = steps.map((s, i) => [
    { text: `${i + 1}`, options: { fill: { color: CYAN_DK }, color: WHITE, bold: true, fontSize: 11, fontFace: FONT, align: "center", valign: "middle" } },
    { text: s[0], options: { fill: { color: i % 2 === 0 ? PANEL : NAVY_2 }, color: CYAN, bold: true, fontSize: 11, fontFace: FONT, valign: "middle" } },
    { text: s[1], options: { fill: { color: i % 2 === 0 ? PANEL : NAVY_2 }, color: WHITE, fontSize: 11, fontFace: FONT, valign: "middle" } },
  ]);
  slide.addTable(rows, {
    x: 0.5,
    y: 1.15,
    w: 9.0,
    colW: [0.5, 2.2, 6.3],
    rowH: 0.46,
    border: { type: "solid", color: NAVY, pt: 1 },
    valign: "middle",
    margin: 4,
  });
})();

/* =====================================================================
 * SLIDE 15 — CONCLUSION
 * ===================================================================== */
(function () {
  const slide = contentSlide("Conclusion & Future Work");
  slide.addText(
    [
      { text: "Summary", options: { color: CYAN, fontSize: 14, bold: true, fontFace: FONT, breakLine: true, paraSpaceAfter: 6 } },
      ...bullets([
        "SecureLens bridges vulnerability detection and developer understanding via RAG-grounded LLM triage.",
      ], { fontSize: 13 }),
      { text: "Expected Outcomes", options: { color: CYAN, fontSize: 14, bold: true, fontFace: FONT, breakLine: true, paraSpaceBefore: 6, paraSpaceAfter: 6 } },
      ...bullets([
        "Reduced alert fatigue and faster fix cycles.",
        "Developer security education embedded into the CI/CD workflow.",
      ], { fontSize: 13 }),
      { text: "Future Work", options: { color: CYAN, fontSize: 14, bold: true, fontFace: FONT, breakLine: true, paraSpaceBefore: 6, paraSpaceAfter: 6 } },
      ...bullets([
        "Add Trivy SCA and OWASP ZAP DAST scanners to the normalisation layer.",
        "Fine-tune a small security-domain LLM on CVE fix pairs.",
        "Deploy as multi-tenant SaaS on AWS ECS.",
        "Add trend analytics and team-level security scoring.",
      ], { fontSize: 13, spaceAfter: 4 }),
    ],
    { x: 0.6, y: 1.1, w: 8.8, h: 4.05, valign: "top" }
  );
})();

/* =====================================================================
 * SLIDE 16 — REFERENCES (IEEE format)
 * ===================================================================== */
(function () {
  const slide = contentSlide("References");
  const refs = [
    "N. S. Mathews, Y. Brus, Y. Aafer, M. Nagappan, and S. McIntosh, \"LLbezpeky: Leveraging large language models for vulnerability detection,\" arXiv:2401.01269, 2024.",
    "A. Stoltman, J. Tang, and H. Cai, \"Representation matters: An empirical study of program representations for LLM vulnerability reasoning,\" arXiv:2606.25356, 2026.",
    "Y. Hou et al., \"Revelio: Cost-efficient agentic memory safety vulnerability detection for repository-scale codebases,\" arXiv:2606.22263, 2026.",
    "S. Neef, L. Jungnickel, and A. B. Buchholz, \"Evaluating LLMs for real-world web vulnerability detection,\" in Proc. AI&CCPS Workshop, ARES, 2026.",
    "M. Sun and G. Meng, \"DREA: Decoupled reasoning and exploration agents for repository-level vulnerability detection,\" in Proc. Internetware, 2026.",
    "R. Fayyazi, R. Taghdimi, and S. J. Yang, \"Advancing TTP analysis: Harnessing the power of large language models with retrieval augmented generation,\" arXiv:2401.00280, 2024.",
    "X. Zhang, J. Sun, Z. Zhang, and Y. Liu, \"Beyond detection: Agentic attack synthesis and simulation for smart contracts,\" arXiv:2607.15673, 2026.",
    "D. Saha, K. T. Hasan, S. Tarek, M. Tehranipoor, and F. Farahmandi, \"VeriChat: An agentic conversational AI assistant for hardware security verification,\" in Proc. IEEE COINS, 2026.",
    "L. R. Muth and M. Margraf, \"Probabilistic agents in deterministic audits: Multi-agent systems for automated IT-Grundschutz audits,\" in Proc. IEEE SysCon, 2026, doi:10.1109/SysCon66367.2026.11503560.",
    "O. Solanki, L. Praharaj, D. Gupta, and M. Gupta, \"Knowledge base poisoning attacks and defense for policy-aware LLM-RAG framework,\" arXiv:2607.04379, 2026.",
    "C. Yang, Z. Zhao, and L. Zhang, \"KernelGPT: Enhanced kernel fuzzing via large language models,\" in Proc. ASPLOS, 2025.",
    "Y. Zhao, H. Chen, L. Lu, Z. Yang, X. Cheng, and H. Wang, \"Neuro-symbolic reasoning for vulnerability detection (LeanGuard),\" arXiv:2607.03963, 2026.",
    "A. Shahriar, H. Cai, H. Benkraouda, G. Wang, and Z. B. Celik, \"Words speak louder than code: Investigating cognitive heuristics in LLM-based code vulnerability detection,\" arXiv:2606.30587, 2026.",
    "D. Yang, R. Wei, and X. Li, \"Ethereum NFT smart contracts: Knowledge-guided vulnerability detection with LLM and code slicing,\" arXiv:2607.21983, 2026.",
    "M. Li, M. Qiu, Z. Peng, H. Fan, S. Fu, J. Ding, and Y. Feng, \"Beyond refusal: A same-lineage study of aligned and abliterated LLMs for vulnerability analysis,\" arXiv:2607.05842, 2026.",
  ];
  const half = Math.ceil(refs.length / 2); // 8 + 7
  const left = refs.slice(0, half);
  const right = refs.slice(half);

  const mk = (arr, startIdx) =>
    arr.map((r, i) => ({
      text: `[${startIdx + i}] ${r}`,
      options: { color: WHITE, fontSize: 8, fontFace: FONT, paraSpaceAfter: 6, breakLine: true, align: "left" },
    }));

  slide.addText(mk(left, 1), { x: 0.4, y: 1.05, w: 4.55, h: 4.2, valign: "top", margin: 0 });
  slide.addText(mk(right, half + 1), { x: 5.05, y: 1.05, w: 4.55, h: 4.2, valign: "top", margin: 0 });
})();

// ---- Write file -----------------------------------------------------------
pres
  .writeFile({ fileName: "SecureLens_Review1.pptx" })
  .then((fn) => console.log("CREATED:", fn))
  .catch((err) => {
    console.error("FAILED:", err);
    process.exit(1);
  });
