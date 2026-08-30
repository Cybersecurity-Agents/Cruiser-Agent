(() => {
  const $ = (id) => document.getElementById(id);

  const state = {
    selected: null,
    logCursor: 0,
    logLines: [],
    stick: true,
  };

  const listEl = $("challengeList");
  const logView = $("logView");

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function pct(n, d) {
    if (!d) return 0;
    return Math.max(0, Math.min(100, Math.round((100 * n) / d)));
  }

  function kindOf(text) {
    if (/\[COUNT\]/.test(text)) return "count";
    if (/\[TOOL\]/.test(text)) return "tool";
    if (/\[Watcher\]/.test(text)) return "watcher";
    if (/\[STAGE\]|\[Session\]/.test(text)) return "stage";
    if (/\[Claude\]/.test(text)) return "claude";
    return "";
  }

  async function getJson(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(String(res.status));
    return res.json();
  }

  function renderVitals(snap) {
    const q = snap.queues || {};
    const wait = ["preprocess", "tier1", "tier2", "tier3"]
      .map((k) => (q[k]?.waiting || []).length)
      .reduce((a, b) => a + b, 0);
    $("vitals").innerHTML = [
      ["在飞", `${snap.inflight || 0}/${snap.max_active || "–"}`],
      ["运行中", snap.running || 0],
      ["排队", wait],
      ["已解", snap.solved_n || 0],
      ["正确 flag", snap.flags_ok || 0],
    ]
      .map(([k, v]) => `<span class="vital">${k}<b>${v}</b></span>`)
      .join("");
    $("pulse").dataset.alive = snap.alive ? "1" : "0";
    $("pulse").textContent = snap.alive ? (snap.local ? "调度中 · 本地" : "调度中") : "无调度心跳";
    $("clock").textContent = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  }

  function renderList(snap) {
    const q = ($("filterCode").value || "").trim().toLowerCase();
    const items = (snap.challenges || []).filter((c) => !q || c.code.toLowerCase().includes(q));
    items.sort((a, b) => Number(b.running) - Number(a.running) || a.code.localeCompare(b.code));
    if (!state.selected && items.length) state.selected = items[0].code;
    listEl.innerHTML = items
      .map((c) => {
        const bar = pct(c.max_count, c.threshold);
        const flags = c.flag_total ? `${c.flag_correct}/${c.flag_total}` : `${c.flag_correct}`;
        return `<button type="button" class="card" data-code="${esc(c.code)}" data-running="${c.running ? 1 : 0}" aria-current="${state.selected === c.code ? "true" : "false"}">
          <span class="code">${esc(c.code)}</span>
          <span class="flags">${flags}</span>
          <span class="stage">${esc(c.stage_label)}${c.difficulty ? " · " + esc(c.difficulty) : ""}</span>
          <span class="mini"><i style="width:${c.running ? bar : 0}%"></i></span>
        </button>`;
      })
      .join("");
  }

  function workerRows(detail) {
    const rows = [
      ...(detail.workers || []).map((w) => ({ ...w, label: `S${w.id}` })),
      ...(detail.solvers || []).map((w) => ({ ...w, label: w.id })),
    ];
    $("nWorkers").textContent = String(rows.filter((w) => w.alive).length);
    if (!rows.length) {
      $("workers").innerHTML = `<div class="row dead"><span>无活动会话</span></div>`;
      return;
    }
    $("workers").innerHTML = rows
      .map((w) => `<div class="row ${w.alive ? "" : "dead"}">
        <span>${esc(w.label)}</span>
        <span>${esc(w.model || w.kind || "")} · ${w.count || 0} 步</span>
        <span class="pid">${w.pid ? "pid " + w.pid : ""}</span>
        ${w.task ? `<span class="task">${esc(w.task)}</span>` : ""}
      </div>`)
      .join("");
  }

  function taskRows(detail) {
    const pending = detail.pending_tasks || [];
    const claimed = detail.claimed_tasks || [];
    $("nTasks").textContent = `${pending.length} 待领 / ${claimed.length} 执行中`;
    const blocks = [];
    if (pending.length) {
      blocks.push(
        pending
          .map((t) => `<div class="bb"><div class="who">${esc(t.id)} · 待认领</div>${esc(t.text)}</div>`)
          .join(""),
      );
    }
    if (claimed.length) {
      blocks.push(
        claimed
          .map(
            (t) =>
              `<div class="bb"><div class="who">${esc(t.worker)} · ${t.age_s || 0}s</div>${esc(t.text)}</div>`,
          )
          .join(""),
      );
    }
    $("tasks").innerHTML = blocks.join("") || `<div class="bb"><div class="who">空</div>任务板暂无方向</div>`;
  }

  function boardRows(detail) {
    const only = $("onlyMethods").checked;
    let entries = [...(detail.blackboard || [])].reverse();
    if (only) entries = entries.filter((e) => e.kind === "flag_method");
    $("nBoard").textContent = String((detail.blackboard || []).length);
    $("board").innerHTML =
      entries
        .map(
          (e) =>
            `<article class="bb" data-kind="${esc(e.kind)}"><div class="who">${esc(e.ts)} · 会话 ${esc(e.worker)}</div>${esc(e.info)}</article>`,
        )
        .join("") || `<div class="bb"><div class="who">空</div>尚无黑板条目</div>`;
  }

  function flagRows(detail) {
    const ok = detail.correct_flags || [];
    const bad = detail.wrong_flags || [];
    $("nFlags").textContent = `${ok.length} 正确 / ${bad.length} 拒绝`;
    $("flagsOk").innerHTML = ok.length
      ? ok.map((x) => `<li>${esc(x.flag)}</li>`).join("")
      : "<li>无</li>";
    $("flagsBad").innerHTML = bad.length
      ? bad.map((f) => `<li>${esc(f)}</li>`).join("")
      : "<li>无</li>";
  }

  function renderDetail(detail) {
    $("emptyState").classList.add("hidden");
    $("detail").classList.remove("hidden");
    $("dCode").textContent = detail.code;
    const bits = [
      detail.stage_label,
      detail.difficulty,
      detail.container_status,
      detail.hint_ready ? "已取提示" : "",
      detail.winner || "",
    ].filter(Boolean);
    $("dMeta").textContent = bits.join(" · ");
    $("dDesc").textContent = detail.description || "无题目描述";
    $("dTarget").textContent = detail.target || "目标未启动";
    if (detail.hint) {
      $("dHintBox").classList.remove("hidden");
      $("dHint").textContent = detail.hint;
    } else {
      $("dHintBox").classList.add("hidden");
      $("dHint").textContent = "";
    }
    const max = detail.max_count || 0;
    const lim = detail.threshold || 0;
    $("dProgressLabel").textContent = lim
      ? `步数 ${max} / ${lim}（本轮阈值） · flag ${detail.flag_correct}/${detail.flag_total || "?"}`
      : `flag ${detail.flag_correct}/${detail.flag_total || "?"}`;
    $("dBar").style.width = `${pct(max, lim)}%`;
    workerRows(detail);
    taskRows(detail);
    boardRows(detail);
    flagRows(detail);
  }

  function appendLogs(payload) {
    const items = payload.items || [];
    if (payload.cursor) state.logCursor = payload.cursor;
    if (!items.length) return;
    const q = ($("logFilter").value || "").trim().toLowerCase();
    for (const it of items) {
      state.logLines.push(it);
      const blob = `${it.worker} ${it.text}`.toLowerCase();
      if (q && !blob.includes(q)) continue;
      const line = document.createElement("span");
      line.className = "log-line";
      line.dataset.k = kindOf(it.text);
      line.innerHTML = `<span class="log-who">${esc(it.worker)}</span>${esc(it.text)}`;
      logView.appendChild(line);
    }
    while (logView.childNodes.length > 500) logView.removeChild(logView.firstChild);
    if (state.stick) logView.scrollTop = logView.scrollHeight;
  }

  function resetLogs() {
    state.logCursor = 0;
    state.logLines = [];
    logView.textContent = "";
  }

  async function tick() {
    const snap = await getJson("/api/snapshot");
    renderVitals(snap);
    renderList(snap);
    if (!state.selected) {
      $("emptyState").classList.remove("hidden");
      $("detail").classList.add("hidden");
      return;
    }
    const detail = await getJson(`/api/challenge?code=${encodeURIComponent(state.selected)}`);
    renderDetail(detail);
    const logs = await getJson(
      `/api/logs?code=${encodeURIComponent(state.selected)}&after=${state.logCursor}&limit=400`,
    );
    appendLogs(logs);
  }

  listEl.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-code]");
    if (!btn) return;
    if (btn.dataset.code === state.selected) return;
    state.selected = btn.dataset.code;
    resetLogs();
    tick().catch(() => {});
  });
  $("filterCode").addEventListener("input", () => tick().catch(() => {}));
  $("onlyMethods").addEventListener("change", () => tick().catch(() => {}));
  $("logFilter").addEventListener("input", () => {
    const q = ($("logFilter").value || "").trim().toLowerCase();
    logView.textContent = "";
    for (const it of state.logLines) {
      const blob = `${it.worker} ${it.text}`.toLowerCase();
      if (q && !blob.includes(q)) continue;
      const line = document.createElement("span");
      line.className = "log-line";
      line.dataset.k = kindOf(it.text);
      line.innerHTML = `<span class="log-who">${esc(it.worker)}</span>${esc(it.text)}`;
      logView.appendChild(line);
    }
    if (state.stick) logView.scrollTop = logView.scrollHeight;
  });
  $("logStick").addEventListener("change", (e) => {
    state.stick = e.target.checked;
  });
  $("logClear").addEventListener("click", () => {
    logView.textContent = "";
  });
  logView.addEventListener("scroll", () => {
    const nearBottom = logView.scrollHeight - logView.scrollTop - logView.clientHeight < 40;
    if (!nearBottom) {
      state.stick = false;
      $("logStick").checked = false;
    }
  });

  tick().catch((err) => {
    $("emptyState").textContent = `无法连接监控接口：${err}`;
  });
  setInterval(() => tick().catch(() => {}), 1000);
})();
