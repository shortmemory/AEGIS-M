"use strict";

const sessionToken = document.querySelector('meta[name="aegis-token"]').content;
const form = document.getElementById("scan-form");
const states = ["idle-state", "running-state", "error-state", "report-state"];
const startButton = document.getElementById("start-scan");
const loadModelsButton = document.getElementById("load-models");
const toast = document.getElementById("toast");
let currentJobId = null;
let toastTimer = null;
let activeScanPromise = null;
let lastReport = null;

function showState(id) {
  for (const stateId of states) document.getElementById(stateId).hidden = stateId !== id;
}

function notify(message) {
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 4200);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("X-Aegis-Token", sessionToken);
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `请求失败（HTTP ${response.status}）`);
  return body;
}

function configFromForm() {
  return {
    base_url: document.getElementById("base-url").value.trim(),
    api_key: document.getElementById("api-key").value.trim(),
    model: document.getElementById("model").value.trim(),
    timeout: Number(document.getElementById("timeout").value),
    allow_insecure_http: document.getElementById("allow-http").checked,
  };
}

document.getElementById("toggle-key").addEventListener("click", (event) => {
  const input = document.getElementById("api-key");
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  event.currentTarget.textContent = visible ? "显示" : "隐藏";
  event.currentTarget.setAttribute("aria-label", visible ? "显示 API Key" : "隐藏 API Key");
});

loadModelsButton.addEventListener("click", async () => {
  if (!form.reportValidity()) return;
  loadModelsButton.disabled = true;
  loadModelsButton.textContent = "读取中…";
  const config = configFromForm();
  try {
    const result = await api("/api/models", { method: "POST", body: JSON.stringify(config) });
    const datalist = document.getElementById("model-options");
    datalist.replaceChildren(...result.models.map((model) => {
      const option = document.createElement("option");
      option.value = model;
      return option;
    }));
    if (result.models.length && !document.getElementById("model").value) {
      document.getElementById("model").value = result.models[0];
    }
    notify(`已读取 ${result.models.length} 个模型`);
  } catch (error) {
    notify(error.message);
  } finally {
    config.api_key = "";
    loadModelsButton.disabled = false;
    loadModelsButton.textContent = "读取模型";
  }
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void startScanFromForm().catch(() => {});
});

async function startScanFromForm() {
  if (activeScanPromise) return activeScanPromise;
  if (!form.reportValidity()) throw new Error("请先完成扫描配置");
  activeScanPromise = performScan();
  try {
    return await activeScanPromise;
  } finally {
    activeScanPromise = null;
  }
}

async function performScan() {
  startButton.disabled = true;
  loadModelsButton.disabled = true;
  showState("running-state");
  updateProgress({ progress: 0, total: 9, current: "正在建立安全连接" });
  const config = configFromForm();
  try {
    const job = await api("/api/scans", { method: "POST", body: JSON.stringify(config) });
    config.api_key = "";
    currentJobId = job.job_id;
    await pollJob(job.job_id);
    return lastReport;
  } catch (error) {
    config.api_key = "";
    showError(error.message);
    throw error;
  } finally {
    startButton.disabled = false;
    loadModelsButton.disabled = false;
  }
}

async function pollJob(jobId) {
  while (true) {
    const job = await api(`/api/scans/${encodeURIComponent(jobId)}`);
    updateProgress(job);
    if (job.state === "complete") {
      renderReport(job.report);
      showState("report-state");
      return;
    }
    if (job.state === "failed") throw new Error(job.error || "扫描失败");
    await new Promise((resolve) => setTimeout(resolve, 650));
  }
}

function updateProgress(job) {
  const total = Math.max(1, job.total || 9);
  const progress = Math.min(total, job.progress || 0);
  document.getElementById("progress-fraction").textContent = `${progress} / ${total}`;
  document.getElementById("progress-bar").style.width = `${Math.round(progress / total * 100)}%`;
  document.getElementById("current-probe").textContent = job.current || "正在扫描";
}

function showError(message) {
  document.getElementById("error-message").textContent = message;
  showState("error-state");
}

document.getElementById("retry-scan").addEventListener("click", () => showState("idle-state"));

function renderReport(report) {
  lastReport = report;
  const summary = report.summary;
  const verdicts = { pass: "通过", suspicious: "需复核", unsafe: "不安全", inconclusive: "无法判定" };
  const severities = { info: "未发现异常", low: "最高：低风险", medium: "最高：中风险", high: "最高：高风险", critical: "最高：严重风险" };
  document.getElementById("risk-score").textContent = summary.risk_score;
  document.getElementById("verdict").textContent = verdicts[summary.verdict] || summary.verdict;
  document.getElementById("severity-text").textContent = severities[summary.highest_severity] || summary.highest_severity;
  document.getElementById("passed-count").textContent = summary.passed;
  document.getElementById("failed-count").textContent = summary.failed;
  document.getElementById("error-count").textContent = summary.errors;
  const ring = document.getElementById("score-ring");
  ring.style.setProperty("--score", summary.risk_score);
  ring.style.setProperty("--risk-color", summary.verdict === "pass" ? "var(--cyan)" : summary.verdict === "unsafe" ? "var(--red)" : "var(--yellow)");
  document.getElementById("target-meta").textContent = `${report.target.base_url}  ·  ${report.target.model}`;

  const list = document.getElementById("results-list");
  list.replaceChildren(...report.results.map(createResultItem));
  const limitations = document.getElementById("limitations-list");
  limitations.replaceChildren(...report.limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}

function createResultItem(result) {
  const item = document.createElement("article");
  item.className = `result-item ${result.status}`;
  const summary = document.createElement("button");
  summary.type = "button";
  summary.className = "result-summary";
  summary.setAttribute("aria-expanded", "false");

  const status = document.createElement("span");
  status.className = "result-status";
  status.textContent = result.status === "pass" ? "✓" : result.status === "error" ? "!" : "×";
  const name = document.createElement("span");
  name.className = "result-name";
  const title = document.createElement("strong");
  title.textContent = result.title;
  const category = document.createElement("small");
  category.textContent = result.category.replaceAll("_", " ");
  name.append(title, category);
  const meta = document.createElement("span");
  meta.className = "result-meta";
  meta.textContent = result.latency_ms ? `${result.latency_ms} ms` : result.status.toUpperCase();
  const chevron = document.createElement("span");
  chevron.className = "chevron";
  chevron.textContent = "›";
  summary.append(status, name, meta, chevron);

  const details = document.createElement("div");
  details.className = "result-details";
  if (!result.findings.length) {
    const clean = document.createElement("p");
    clean.className = "field-help";
    clean.textContent = "本轮没有观察到安全偏差。";
    details.append(clean);
  } else {
    for (const finding of result.findings) details.append(createFinding(finding));
  }
  if (result.response_excerpt !== null && result.response_excerpt !== undefined) {
    const evidenceButton = document.createElement("button");
    evidenceButton.type = "button";
    evidenceButton.className = "evidence-toggle";
    evidenceButton.textContent = "查看受限响应证据";
    const evidence = document.createElement("pre");
    evidence.className = "evidence";
    evidence.hidden = true;
    evidence.textContent = JSON.stringify(result.response_excerpt, null, 2);
    evidenceButton.addEventListener("click", () => {
      evidence.hidden = !evidence.hidden;
      evidenceButton.textContent = evidence.hidden ? "查看受限响应证据" : "收起响应证据";
    });
    details.append(evidenceButton, evidence);
  }
  summary.addEventListener("click", () => {
    const open = item.classList.toggle("open");
    summary.setAttribute("aria-expanded", String(open));
  });
  item.append(summary, details);
  return item;
}

function createFinding(finding) {
  const block = document.createElement("div");
  block.className = `finding ${finding.severity}`;
  const head = document.createElement("div");
  head.className = "finding-head";
  const severity = document.createElement("span");
  severity.className = "severity";
  severity.textContent = finding.severity.toUpperCase();
  const title = document.createElement("strong");
  title.textContent = finding.title;
  head.append(severity, title);
  const detail = document.createElement("p");
  detail.textContent = finding.detail;
  block.append(head, detail);
  return block;
}

document.getElementById("download-report").addEventListener("click", async () => {
  if (!currentJobId) return;
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(currentJobId)}/report.json`, {
      headers: { "X-Aegis-Token": sessionToken }, cache: "no-store"
    });
    if (!response.ok) throw new Error("报告下载失败");
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aegis-report-${currentJobId}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) {
    notify(error.message);
  }
});

function registerWebMcpTools() {
  const context = document.modelContext;
  if (!context?.registerTool) return;
  const emptySchema = { type: "object", properties: {}, additionalProperties: false };
  try {
    void Promise.resolve(context.registerTool({
      name: "start_relay_security_scan",
      title: "启动中转站安全扫描",
      description: "使用页面中已经填写的目标、模型和密钥启动完整安全扫描。密钥不作为工具参数返回。",
      inputSchema: emptySchema,
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      async execute() {
        const report = await startScanFromForm();
        if (!report) throw new Error("扫描没有生成报告");
        return {
          verdict: report.summary.verdict,
          risk_score: report.summary.risk_score,
          passed: report.summary.passed,
          failed: report.summary.failed,
          errors: report.summary.errors,
        };
      },
    })).catch(() => {});
    void Promise.resolve(context.registerTool({
      name: "read_scan_summary",
      title: "读取扫描摘要",
      description: "读取页面中最近一次安全扫描的结论和风险统计，不启动新请求。",
      inputSchema: emptySchema,
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute() {
        if (!lastReport) return { state: activeScanPromise ? "running" : "not_started" };
        return { state: "complete", target: lastReport.target, summary: lastReport.summary };
      },
    })).catch(() => {});
  } catch (_) {
    // WebMCP is optional and feature-detected; the visible interface remains fully functional.
  }
}

registerWebMcpTools();
