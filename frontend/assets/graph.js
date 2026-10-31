/* KillChain interactive attack graph — force-directed SVG with pan/zoom,
   node dragging, selection, observed vs inferred edge styles. */
(function () {
  const NS = "http://www.w3.org/2000/svg";

  const KIND_STYLE = {
    ip: { color: "#38e1ff", r: 13, glyph: "IP" },
    user: { color: "#34d399", r: 13, glyph: "U" },
    host: { color: "#7dd3fc", r: 16, glyph: "H" },
    process: { color: "#c4b5fd", r: 11, glyph: ">" },
  };

  function el(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }

  class AttackGraph {
    constructor(container, opts = {}) {
      this.container = typeof container === "string" ? document.querySelector(container) : container;
      this.opts = opts; // onSelectNode, onSelectEdge, onEmpty
      this.svg = el("svg", { id: "graph-svg" });
      this.container.appendChild(this.svg);
      this.defs = el("defs", {}, this.svg);
      const marker = el("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 22, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, this.defs);
      el("path", { d: "M 0 1 L 9 5 L 0 9 z", fill: "#2b4166" }, marker);
      const markerSel = el("marker", { id: "arrowSel", viewBox: "0 0 10 10", refX: 22, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, this.defs);
      el("path", { d: "M 0 1 L 9 5 L 0 9 z", fill: "#38e1ff" }, markerSel);

      this.viewport = el("g", { class: "viewport" }, this.svg);
      this.edgeLayer = el("g", {}, this.viewport);
      this.labelLayer = el("g", {}, this.viewport);
      this.nodeLayer = el("g", {}, this.viewport);

      this.nodes = []; this.edges = []; this.byId = {};
      this.transform = { x: 0, y: 0, k: 1 };
      this.selected = null;
      this.alpha = 1;
      this._initPanZoom();
    }

    setData(data) {
      this.nodes = []; this.edges = []; this.byId = {};
      this.edgeLayer.innerHTML = ""; this.nodeLayer.innerHTML = ""; this.labelLayer.innerHTML = "";
      this.selected = null; this.alpha = 1;

      const W = this.container.clientWidth || 900, H = this.container.clientHeight || 520;
      const rad = Math.min(W, H) * 0.36;
      data.nodes.forEach((n, i) => {
        const a = (2 * Math.PI * i) / data.nodes.length;
        const gnode = {
          ...n, x: W / 2 + rad * Math.cos(a) + (Math.random() - 0.5) * 40,
          y: H / 2 + rad * Math.sin(a) + (Math.random() - 0.5) * 40,
          vx: 0, vy: 0, el: null, deg: 0,
        };
        this.nodes.push(gnode); this.byId[n.id] = gnode;
      });
      data.edges.forEach((e) => {
        const s = this.byId[e.source], t = this.byId[e.target];
        if (!s || !t) return;
        s.deg++; t.deg++;
        this.edges.push({ ...e, s, t, el: null, labelEl: null });
      });
      this._renderEdges();
      this._renderNodes();
      this.fit();
      this.start();
      if (!this.nodes.length && this.opts.onEmpty) this.opts.onEmpty();
    }

    _renderEdges() {
      this.edges.forEach((e) => {
        const cls = ["g-edge"];
        if (!e.observed) cls.push("inferred");
        if (e.severity && e.observed) cls.push("sev-" + e.severity);
        e.el = el("line", { class: cls.join(" "), "marker-end": "url(#arrow)" }, this.edgeLayer);
        e.labelEl = el("text", { class: "g-edge-label", "text-anchor": "middle", opacity: 0 }, this.labelLayer);
        e.labelEl.textContent = e.label || e.kind;
        e.el.addEventListener("click", (ev) => {
          ev.stopPropagation();
          this._selectEdge(e);
        });
      });
    }

    _renderNodes() {
      this.nodes.forEach((n) => {
        const st = KIND_STYLE[n.kind] || KIND_STYLE.ip;
        const g = el("g", { class: "g-node" }, this.nodeLayer);
        const color = n.role === "attacker_infra" ? "#ff4d6a" : st.color;
        const r = n.kind === "host" ? st.r + Math.min(n.deg, 4) : st.r;
        const inferred = n.label && n.label.includes("INFERRED");
        if (inferred) {
          el("circle", { class: "body", r: r + 4, fill: "none", stroke: "#7c5cff", "stroke-dasharray": "4 3", "stroke-width": 1.5 }, g);
        }
        const body = el("circle", { class: "body", r, fill: "#0b1220", stroke: color, style: `color:${color}` }, g);
        if (n.role === "attacker_infra") {
          el("circle", { r: r + 6, fill: "none", stroke: "rgba(255,77,106,.5)", "stroke-width": 1.5 }, g);
        }
        const glyph = el("text", {
          "text-anchor": "middle", dy: "4", "font-size": n.kind === "process" ? 11 : 12,
          "font-family": "monospace", fill: color, "font-weight": 700, "pointer-events": "none",
        }, g);
        glyph.textContent = st.glyph;
        const label = el("text", { class: "g-label", "text-anchor": "middle", y: r + 15 }, g);
        label.textContent = (n.label || n.ident || "").slice(0, 26);
        const sub = el("text", { class: "g-sub", "text-anchor": "middle", y: r + 27 }, g);
        sub.textContent = n.kind === "ip" ? (n.external ? "external" : "ip") : n.kind;

        n.el = g; n.r = r; n.color = color;
        g.addEventListener("pointerdown", (ev) => this._dragStart(ev, n));
        g.addEventListener("click", (ev) => { ev.stopPropagation(); this._selectNode(n); });
      });
      this.svg.addEventListener("click", () => this._deselect());
    }

    _selectNode(n) {
      this.selected = n;
      this.nodes.forEach((m) => m.el.classList.remove("selected", "dim"));
      this.edges.forEach((e) => e.el.classList.remove("selected"));
      // highlight neighborhood
      const keep = new Set([n.id]);
      this.edges.forEach((e) => {
        if (e.source === n.id) { keep.add(e.target); e.el.classList.add("selected"); }
        if (e.target === n.id) { keep.add(e.source); e.el.classList.add("selected"); }
      });
      this.nodes.forEach((m) => { if (!keep.has(m.id)) m.el.classList.add("dim"); });
      n.el.classList.add("selected");
      if (this.opts.onSelectNode) this.opts.onSelectNode(n, this.edges.filter(e => e.source === n.id || e.target === n.id));
    }

    _selectEdge(e) {
      this.edges.forEach((x) => x.el.classList.remove("selected"));
      e.el.classList.add("selected");
      e.el.setAttribute("marker-end", "url(#arrowSel)");
      if (this.opts.onSelectEdge) this.opts.onSelectEdge(e);
    }

    _deselect() {
      this.selected = null;
      this.nodes.forEach((m) => m.el.classList.remove("selected", "dim"));
      this.edges.forEach((e) => { e.el.classList.remove("selected"); e.el.setAttribute("marker-end", "url(#arrow)"); });
      if (this.opts.onSelectNode) this.opts.onSelectNode(null);
    }

    // ----- physics -----
    start() {
      if (this._raf) cancelAnimationFrame(this._raf);
      const tick = () => {
        this._step();
        if (this.alpha > 0.015) this._raf = requestAnimationFrame(tick);
      };
      this._raf = requestAnimationFrame(tick);
    }

    _step() {
      const N = this.nodes, W = this.container.clientWidth, H = this.container.clientHeight;
      this.alpha *= 0.992;
      const rep = 2600, kAttr = 0.03;
      for (let i = 0; i < N.length; i++) {
        const a = N[i];
        for (let j = i + 1; j < N.length; j++) {
          const b = N[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let d2 = dx * dx + dy * dy || 1;
          const f = (rep * this.alpha) / d2;
          const d = Math.sqrt(d2);
          dx /= d; dy /= d;
          a.vx -= dx * f; a.vy -= dy * f;
          b.vx += dx * f; b.vy += dy * f;
        }
        // center gravity
        a.vx += (W / 2 - a.x) * 0.0035 * this.alpha;
        a.vy += (H / 2 - a.y) * 0.0045 * this.alpha;
      }
      const spring = 0.06, restLen = 130;
      this.edges.forEach((e) => {
        let dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - restLen) * spring * this.alpha;
        dx /= d; dy /= d;
        e.s.vx += dx * f; e.s.vy += dy * f;
        e.t.vx -= dx * f; e.t.vy -= dy * f;
      });
      N.forEach((n) => {
        if (n._drag) { n.vx = n.vy = 0; return; }
        n.vx *= 0.86; n.vy *= 0.86;
        n.x = Math.max(40, Math.min(W - 40, n.x + Math.max(-30, Math.min(30, n.vx))));
        n.y = Math.max(40, Math.min(H - 40, n.y + Math.max(-30, Math.min(30, n.vy))));
      });
      this._paint();
    }

    _paint() {
      this.nodes.forEach((n) => {
        n.el.setAttribute("transform", `translate(${n.x},${n.y})`);
      });
      this.edges.forEach((e) => {
        const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const sx = e.s.x + (dx / d) * (e.s.r + 3), sy = e.s.y + (dy / d) * (e.s.r + 3);
        const tx = e.t.x - (dx / d) * (e.t.r + 8), ty = e.t.y - (dy / d) * (e.t.r + 8);
        e.el.setAttribute("x1", sx); e.el.setAttribute("y1", sy);
        e.el.setAttribute("x2", tx); e.el.setAttribute("y2", ty);
        e.labelEl.setAttribute("x", (sx + tx) / 2); e.labelEl.setAttribute("y", (sy + ty) / 2 - 5);
      });
      this.viewport.setAttribute("transform",
        `translate(${this.transform.x},${this.transform.y}) scale(${this.transform.k})`);
    }

    fit() {
      const W = this.container.clientWidth, H = this.container.clientHeight;
      if (!this.nodes.length) return;
      const xs = this.nodes.map(n => n.x), ys = this.nodes.map(n => n.y);
      const minX = Math.min(...xs) - 60, maxX = Math.max(...xs) + 60;
      const minY = Math.min(...ys) - 60, maxY = Math.max(...ys) + 60;
      const k = Math.min(1.15, Math.min(W / (maxX - minX), H / (maxY - minY)));
      this.transform = { k, x: W / 2 - k * (minX + maxX) / 2, y: H / 2 - k * (minY + maxY) / 2 };
      this._paint();
    }

    _initPanZoom() {
      const svg = this.svg;
      let panning = false, px = 0, py = 0;
      svg.addEventListener("pointerdown", (ev) => {
        if (ev.target.closest(".g-node")) return;
        panning = true; px = ev.clientX; py = ev.clientY;
        svg.classList.add("dragging");
      });
      window.addEventListener("pointermove", (ev) => {
        if (panning) {
          this.transform.x += ev.clientX - px;
          this.transform.y += ev.clientY - py;
          px = ev.clientX; py = ev.clientY;
          this._paint();
        }
      });
      window.addEventListener("pointerup", () => { panning = false; svg.classList.remove("dragging"); });
      svg.addEventListener("wheel", (ev) => {
        ev.preventDefault();
        const k2 = Math.min(2.6, Math.max(0.3, this.transform.k * (ev.deltaY < 0 ? 1.09 : 0.92)));
        const rect = svg.getBoundingClientRect();
        const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
        this.transform.x = mx - k2 * (mx - this.transform.x) / this.transform.k;
        this.transform.y = my - k2 * (my - this.transform.y) / this.transform.k;
        this.transform.k = k2;
        this._paint();
      }, { passive: false });
    }

    _dragStart(ev, n) {
      ev.stopPropagation();
      n._drag = true;
      const svg = this.svg;
      const move = (e) => {
        if (!n._drag) return;
        const rect = svg.getBoundingClientRect();
        const pt = svg.createSVGPoint();
        pt.x = e.clientX - rect.left; pt.y = e.clientY - rect.top;
        const sp = pt.matrixTransform(svg.getScreenCTM().inverse());
        // account for viewport transform
        const k = this.transform.k;
        n.x = (pt.x - this.transform.x) / k;
        n.y = (pt.y - this.transform.y) / k;
        this.alpha = Math.max(this.alpha, 0.35);
        this.start();
      };
      const up = () => { n._drag = false; window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
    }
  }

  window.KillGraph = AttackGraph;
})();
