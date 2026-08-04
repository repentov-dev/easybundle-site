(() => {
  "use strict";

  // Reset scroll position on load
  window.scrollTo(0, 0);

  /* ═══════════════════════════════════════════════════════
     EASYBUNDLE — main.js
     Animation timings from Tokens::Anim (Tokens.h)
     Approach coefficients from EasyBundleLookAndFeel::tickUiAnimations()
     ═══════════════════════════════════════════════════════ */

  // ── Tokens::Anim ──
  const ANIM = {
    rowShow:   0.18,   // Tokens::Anim::rowShow
    rowHide:   0.30,   // Tokens::Anim::rowHide
    gsSlot:    0.24,   // Tokens::Anim::gsSlot
    aboutFade: 0.18,   // Tokens::Anim::aboutFade
  };

  // ── Approach coefficients from tickUiAnimations() ──
  // Oval chips: press 0.15, hover 0.16, morph lags hover 0.16 / 0.28 press
  // Regular chips: press 0.28, hover 0.22
  const COEF = {
    buttonOn:       0.18,
    buttonPress:    0.28,
    buttonHover:    0.22,
    ovalPress:      0.15,
    ovalHover:      0.16,
    ovalMorph:      0.16,
    ovalMorphPress: 0.28,
    ovalFocus:      0.16,
    sliderGrab:     0.16,
    sliderPress:    0.30,
  };

  const plugins = document.querySelectorAll(".plugin");
  const sections = document.querySelectorAll(".plugin");
  const railLinks = [...document.querySelectorAll(".rail a[href^='#']")];
  const rail = document.querySelector(".rail");
  const isMobileLang = () => window.matchMedia("(max-width: 900px)").matches;

  /* ── Scroll reveal — Tokens::Anim::rowShow timing ── */
  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) entry.target.classList.add("is-inview");
      }
    },
    { threshold: 0.15, rootMargin: "0px 0px -60px 0px" }
  );
  plugins.forEach((el) => io.observe(el));
  const footer = document.querySelector(".footer");
  if (footer) io.observe(footer);

  /* ── Floating nav hide/show on scroll ── */
  let lastScroll = 0;
  let ticking = false;

  function onScroll() {
    if (!ticking) {
      requestAnimationFrame(() => {
        const currentScroll = window.scrollY;

        if (currentScroll > lastScroll && currentScroll > 80) {
          rail.classList.add("is-hidden");
        } else {
          rail.classList.remove("is-hidden");
        }

        lastScroll = currentScroll;
        ticking = false;
      });
      ticking = true;
    }
  }

window.addEventListener("scroll", onScroll, { passive: true });

  /* ── Active section spy for floating nav ── */
  const spy = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const id = entry.target.id;
        railLinks.forEach((a) => {
          a.classList.toggle("is-active", a.getAttribute("href") === `#${id}`);
        });
      }
    },
    { rootMargin: "-40% 0px -45% 0px", threshold: 0 }
  );
  sections.forEach((el) => { if (el.id) spy.observe(el); });



  /* ── Smooth scroll for nav links ── */
  railLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      const href = link.getAttribute("href");
      if (href && href.startsWith("#")) {
        e.preventDefault();
        const target = document.querySelector(href);
        if (target) {
          target.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    });
  });

  /* ── Parallax on hero atmosphere ── */
  const atmosphere = document.querySelector(".hero__atmosphere");
  if (atmosphere && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    window.addEventListener("scroll", () => {
      requestAnimationFrame(() => {
        const scrolled = window.scrollY;
        if (scrolled < window.innerHeight) {
          atmosphere.style.transform = `translateY(${scrolled * 0.3}px)`;
        }
      });
    }, { passive: true });
  }

  /* ── Knob hover interaction — mimics sliderGrab approach (0.16) ── */
  document.querySelectorAll(".knob i").forEach((knob) => {
    knob.addEventListener("mouseenter", () => {
      knob.style.boxShadow = `inset 0 0 0 7px var(--bg), 0 0 12px color-mix(in srgb, var(--ui-accent, var(--accent)) 15%, transparent)`;
    });
    knob.addEventListener("mouseleave", () => {
      knob.style.boxShadow = "inset 0 0 0 7px var(--bg)";
    });
  });

  /* ── Decorative UI chips (plugin mocks) ── */
  document.querySelectorAll(".ui__chips span, .ui__modes span").forEach((chip) => {
    chip.style.transition = `all ${COEF.ovalHover}s ease`;
  });

  /* ═══════════════════════════════════════════════════════
     EasyUI2 oval morph buttons
     paintOvalButtonOverParent + tickUiAnimations (oval path)
     — morph lags hover; shape bulges toward cursor
     — press: uniform shrink 10%; label stays on rest bounds
     ═══════════════════════════════════════════════════════ */
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function approach(v, target, coef) {
    let next = v + (target - v) * coef;
    if (Math.abs(target - next) < 0.002) next = target;
    return next;
  }

  function lerpChannel(a, b, t) {
    return Math.round(a + (b - a) * t);
  }

  function lerpHex(a, b, t) {
    const parse = (hex) => {
      const n = hex.replace("#", "");
      return [
        parseInt(n.slice(0, 2), 16),
        parseInt(n.slice(2, 4), 16),
        parseInt(n.slice(4, 6), 16),
      ];
    };
    const [ar, ag, ab] = parse(a);
    const [br, bg, bb] = parse(b);
    return `rgb(${lerpChannel(ar, br, t)}, ${lerpChannel(ag, bg, t)}, ${lerpChannel(ab, bb, t)})`;
  }

  const CHIP_OFF = "#1e1e1e";
  const CHIP_ON = "#f5f5f5";
  const BUY_ON = "#FF3D6E";
  const TEXT_OFF = "#cfcfcf";
  const TEXT_ON = "#0a0a0a";
  const PRESS_SCALE = 0.10;
  const MORPH_OVERFLOW = 14; // kOverflow in paintOvalButtonOverParent

  function isChipOn(el) {
    if (el.classList.contains("btn--primary") || el.classList.contains("btn--buy")) return true;
    if (el.classList.contains("rail__langs")) return true; // lang chip always "on" fill
    if (el.classList.contains("btn--ghost")) return false;
    return el.classList.contains("is-active");
  }

  function chipOnColour(el) {
    if (el.classList.contains("btn--buy")) return BUY_ON;
    return CHIP_ON;
  }

  /** Sample a capsule / rounded-rect outline (matches PathFlatteningIterator). */
  function samplePill(x, y, w, h, corner, step) {
    const r = Math.min(corner, w * 0.5, h * 0.5);
    const pts = [];
    const push = (px, py) => {
      const last = pts[pts.length - 1];
      if (!last || Math.hypot(last.x - px, last.y - py) > 0.25) pts.push({ x: px, y: py });
    };

    // Top edge (left → right)
    for (let px = x + r; px <= x + w - r; px += step) push(px, y);
    // Top-right arc
    for (let a = -Math.PI / 2; a <= 0; a += step / Math.max(r, 1)) {
      push(x + w - r + Math.cos(a) * r, y + r + Math.sin(a) * r);
    }
    // Right edge
    for (let py = y + r; py <= y + h - r; py += step) push(x + w, py);
    // Bottom-right arc
    for (let a = 0; a <= Math.PI / 2; a += step / Math.max(r, 1)) {
      push(x + w - r + Math.cos(a) * r, y + h - r + Math.sin(a) * r);
    }
    // Bottom edge (right → left)
    for (let px = x + w - r; px >= x + r; px -= step) push(px, y + h);
    // Bottom-left arc
    for (let a = Math.PI / 2; a <= Math.PI; a += step / Math.max(r, 1)) {
      push(x + r + Math.cos(a) * r, y + h - r + Math.sin(a) * r);
    }
    // Left edge
    for (let py = y + h - r; py >= y + r; py -= step) push(x, py);
    // Top-left arc
    for (let a = Math.PI; a <= (Math.PI * 3) / 2; a += step / Math.max(r, 1)) {
      push(x + r + Math.cos(a) * r, y + r + Math.sin(a) * r);
    }

    if (pts.length) pts.push({ ...pts[0] });
    return pts;
  }

  /** Morph pill toward focus — same math as paintOvalButtonOverParent. */
  function morphPillPoints(base, bounds, focusX, focusY, morph, opts = {}) {
    if (morph <= 0.01 || base.length < 3) return base;

    const overflow = opts.overflow != null ? opts.overflow : MORPH_OVERFLOW;
    const bulgeBase = opts.bulgeBase != null ? opts.bulgeBase : 6;
    const bulgeGain = opts.bulgeGain != null ? opts.bulgeGain : 5.5;
    const sigmaScale = opts.sigmaScale != null ? opts.sigmaScale : 0.3;

    const ndx = (focusX - 0.5) * 2;
    const ndy = (focusY - 0.5) * 2;
    const edge = Math.min(1, Math.max(0, Math.hypot(ndx, ndy)));
    const centerWeight = 1 - 0.65 * edge;
    const bulge = (bulgeBase + bulgeGain * morph) * centerWeight;
    const sigma = Math.max(12, bounds.w * sigmaScale);
    const cx = bounds.x + bounds.w * 0.5;
    const cy = bounds.y + bounds.h * 0.5;
    const focus = {
      x: bounds.x + focusX * bounds.w,
      y: bounds.y + focusY * bounds.h,
    };
    const lim = {
      x0: bounds.x - overflow,
      y0: bounds.y - overflow,
      x1: bounds.x + bounds.w + overflow,
      y1: bounds.y + bounds.h + overflow,
    };

    // Drop closing duplicate so normals wrap cleanly around the ring
    let ring = base;
    if (ring.length >= 2) {
      const a = ring[0];
      const b = ring[ring.length - 1];
      if (Math.hypot(a.x - b.x, a.y - b.y) < 0.5) ring = ring.slice(0, -1);
    }

    const out = [];
    for (let i = 0; i < ring.length; i++) {
      const p = ring[i];
      const prev = ring[(i + ring.length - 1) % ring.length];
      const next = ring[(i + 1) % ring.length];
      let tx = next.x - prev.x;
      let ty = next.y - prev.y;
      const len = Math.hypot(tx, ty);
      let nx = 0;
      let ny = 0;
      if (len > 1e-4) {
        tx /= len;
        ty /= len;
        nx = ty;
        ny = -tx;
        if (nx * (p.x - cx) + ny * (p.y - cy) < 0) {
          nx = -nx;
          ny = -ny;
        }
      }
      const d = Math.hypot(focus.x - p.x, focus.y - p.y);
      const fall = Math.exp(-0.5 * (d / sigma) * (d / sigma));
      let x = p.x + nx * bulge * fall * morph;
      let y = p.y + ny * bulge * fall * morph;
      x = Math.min(lim.x1, Math.max(lim.x0, x));
      y = Math.min(lim.y1, Math.max(lim.y0, y));
      out.push({ x, y });
    }
    return out;
  }

  function paintChip(st) {
    const { el, canvas, ctx, dpr } = st;
    const w = el.offsetWidth;
    const h = el.offsetHeight;
    if (w < 1 || h < 1) return;

    const pad = MORPH_OVERFLOW + 2;
    const cw = w + pad * 2;
    const ch = h + pad * 2;
    if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
      canvas.width = Math.round(cw * dpr);
      canvas.height = Math.round(ch * dpr);
      canvas.style.width = `${cw}px`;
      canvas.style.height = `${ch}px`;
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cw, ch);

    // Rest bounds in canvas space (centred with overflow pad)
    const rest = { x: pad, y: pad, w, h };
    const scale = 1 - PRESS_SCALE * st.press;
    const bounds = {
      x: rest.x + rest.w * (1 - scale) * 0.5,
      y: rest.y + rest.h * (1 - scale) * 0.5,
      w: rest.w * scale,
      h: rest.h * scale,
    };
    const corner = Math.min(bounds.w, bounds.h) * 0.5;

    let pts = samplePill(bounds.x, bounds.y, bounds.w, bounds.h, corner, 0.35);
    if (!reduceMotion) {
      pts = morphPillPoints(pts, bounds, st.focusX, st.focusY, st.morph);
    }

    const fill = el.classList.contains("btn--ghost")
      ? "transparent"
      : lerpHex(CHIP_OFF, chipOnColour(el), st.on);

    ctx.beginPath();
    if (pts.length) {
      ctx.moveTo(pts[0].x, pts[0].y);
      for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
      ctx.closePath();
    }

    if (el.classList.contains("btn--ghost")) {
      ctx.strokeStyle = st.on > 0.5 ? CHIP_ON : "#222222";
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.fillStyle = "rgba(255,255,255,0.03)";
      ctx.fill();
    } else {
      ctx.fillStyle = fill;
      ctx.fill();
    }

    // Lang switch: paint labels on canvas AFTER fill (EasyUI2 order) — always #0a0a0a on white
    if (el.classList.contains("rail__langs")) {
      const active = el.querySelector(".rail__lang.is-active");
      const activeLang = (active && active.dataset.lang) || "en";
      const expand = st.expand || 0;
      ctx.font = "700 12px " + (getComputedStyle(document.body).getPropertyValue("--mono") || "ui-monospace, monospace");
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      const cy = rest.y + rest.h * 0.5;
      const vertical = isMobileLang();

      if (expand < 0.08) {
        ctx.fillStyle = TEXT_ON;
        ctx.fillText(activeLang.toUpperCase(), rest.x + rest.w * 0.5, cy);
      } else if (vertical) {
        // Vertical morph: EN on top, RU below
        const enY = rest.y + rest.h * 0.24;
        const ruY = rest.y + rest.h * 0.76;
        const enColor = activeLang === "en" ? TEXT_ON : "#6a6a6a";
        const ruColor = activeLang === "ru" ? TEXT_ON : "#6a6a6a";
        const a = Math.min(1, Math.max(0, (expand - 0.08) / 0.5));
        ctx.globalAlpha = a;
        ctx.fillStyle = enColor;
        ctx.fillText("EN", rest.x + rest.w * 0.5, enY);
        ctx.fillStyle = ruColor;
        ctx.fillText("RU", rest.x + rest.w * 0.5, ruY);
        ctx.globalAlpha = 1;
        if (expand < 0.55) {
          ctx.globalAlpha = 1 - a;
          ctx.fillStyle = TEXT_ON;
          ctx.fillText(activeLang.toUpperCase(), rest.x + rest.w * 0.5, cy);
          ctx.globalAlpha = 1;
        }
      } else {
        const mid = rest.x + rest.w * 0.5;
        const leftX = rest.x + rest.w * 0.28;
        const rightX = rest.x + rest.w * 0.72;
        const enColor = activeLang === "en" ? TEXT_ON : "#6a6a6a";
        const ruColor = activeLang === "ru" ? TEXT_ON : "#6a6a6a";
        const a = Math.min(1, Math.max(0, (expand - 0.08) / 0.5));
        ctx.globalAlpha = a;
        ctx.fillStyle = enColor;
        ctx.fillText("EN", leftX, cy);
        ctx.fillStyle = ruColor;
        ctx.fillText("RU", rightX, cy);
        ctx.globalAlpha = 1;
        // While mostly collapsed, keep active label readable in the center
        if (expand < 0.55) {
          ctx.globalAlpha = 1 - a;
          ctx.fillStyle = TEXT_ON;
          ctx.fillText(activeLang.toUpperCase(), mid, cy);
          ctx.globalAlpha = 1;
        }
      }
    } else if (!el.classList.contains("btn--ghost")) {
      el.style.setProperty("--btn-ink", lerpHex(TEXT_OFF, TEXT_ON, st.on));
    } else {
      el.style.setProperty("--btn-ink", TEXT_OFF);
    }
  }

  const chipEls = [...document.querySelectorAll(".btn, .rail a:not(.rail__lang), .rail__langs")];
  const chipState = new Map();

  chipEls.forEach((el) => {
    const isLangSwitch = el.classList.contains("rail__langs");

    // Wrap label so it stays above the morph canvas (skip lang switch — has own buttons)
    if (!isLangSwitch && !el.querySelector(".chip__label")) {
      const label = document.createElement("span");
      label.className = "chip__label";
      while (el.firstChild) label.appendChild(el.firstChild);
      // Keep i18n on the text node host so setLang won't wipe the canvas
      if (el.hasAttribute("data-i18n")) {
        label.setAttribute("data-i18n", el.getAttribute("data-i18n"));
        el.removeAttribute("data-i18n");
      }
      el.appendChild(label);
    }

    const canvas = document.createElement("canvas");
    canvas.className = "chip__canvas";
    canvas.setAttribute("aria-hidden", "true");
    el.insertBefore(canvas, el.firstChild);

    const ctx = canvas.getContext("2d");
    const on0 = isChipOn(el) ? 1 : 0;
    const st = {
      el,
      canvas,
      ctx,
      dpr: Math.min(window.devicePixelRatio || 1, 2),
      on: on0,
      press: 0,
      hover: 0,
      morph: 0,
      expand: 0,
      focusX: 0.5,
      focusY: 0.5,
      over: false,
      down: false,
      mx: 0.5,
      my: 0.5,
      isLangSwitch,
    };
    chipState.set(el, st);

    el.addEventListener("pointerenter", () => { st.over = true; });
    el.addEventListener("pointerleave", () => {
      st.over = false;
      st.down = false;
    });
    el.addEventListener("pointermove", (e) => {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) {
        st.mx = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
        st.my = Math.min(1, Math.max(0, (e.clientY - r.top) / r.height));
      }
    });
    el.addEventListener("pointerdown", (e) => {
      if (e.button === 0) st.down = true;
    });
    el.addEventListener("pointerup", () => { st.down = false; });
    el.addEventListener("pointercancel", () => {
      st.down = false;
      st.over = false;
    });

    if (isLangSwitch) {
      // Fixed chip widths — no measure/translate tricks
      st.langCollapsedW = 44;
      st.langExpandedW = 44 * 2 + 6; // two chips + gap
      st.langCollapsedH = 28;
      st.langExpandedH = 28 * 2 + 6; // two chips + gap, vertical
      st.tapped = false;
      st.syncLangWidth = () => {};
      el.addEventListener("click", (e) => {
        if (!isMobileLang()) return;
        e.stopPropagation();
        const ls = document.getElementById("langSwitch");
        if (ls && ls.classList.contains("is-open")) {
          closeMobileLang();
        } else {
          openMobileLang();
        }
      });
    }

    paintChip(st);
  });

  window.addEventListener("blur", () => {
    chipState.forEach((st) => {
      st.down = false;
      st.over = false;
    });
  });

  function tickChipAnimations() {
    for (const st of chipState.values()) {
      const onTarget = isChipOn(st.el) ? 1 : 0;
      st.on = approach(st.on, onTarget, COEF.buttonOn);
      st.press = approach(st.press, st.down ? 1 : 0, COEF.ovalPress);
      st.hover = approach(st.hover, st.over ? 1 : 0, COEF.ovalHover);
      st.morph = approach(
        st.morph,
        st.hover,
        st.down ? COEF.ovalMorphPress : COEF.ovalMorph
      );

      if (st.isLangSwitch) {
        if (isMobileLang()) {
          // Mobile: chip morphs downward (vertical growth) on tap
          const target = st.tapped ? 1 : 0;
          st.expand = approach(st.expand, target, target ? 0.18 : 0.16);
          const ch = st.langCollapsedH || 28;
          const xh = st.langExpandedH || 62;
          st.el.style.width = "";
          st.el.style.height = `${ch + (xh - ch) * st.expand}px`;
          st.el.classList.toggle("is-open", st.expand > 0.08);
        } else {
          st.expand = approach(st.expand, st.over ? 1 : 0, st.over ? 0.18 : 0.16);
          const c = st.langCollapsedW || 44;
          const x = st.langExpandedW || 94;
          st.el.style.width = `${c + (x - c) * st.expand}px`;
          st.el.style.height = "";
          st.el.classList.toggle("is-open", st.expand > 0.08);
        }
      }

      if (st.over || st.down) {
        st.focusX = approach(st.focusX, st.mx, COEF.ovalFocus);
        st.focusY = approach(st.focusY, st.my, COEF.ovalFocus);
      }

      paintChip(st);
    }
    requestAnimationFrame(tickChipAnimations);
  }

  requestAnimationFrame(tickChipAnimations);

  // Repaint after i18n / layout shifts
  const chipResize = new ResizeObserver(() => {
    chipState.forEach((st) => {
      st.dpr = Math.min(window.devicePixelRatio || 1, 2);
      paintChip(st);
    });
  });
  chipEls.forEach((el) => chipResize.observe(el));

  /* ── Plugin UI tilt on mouse move — subtle parallax ── */
  document.querySelectorAll(".ui").forEach((ui) => {
    const parent = ui.closest(".plugin__shot");
    if (!parent) return;

    parent.addEventListener("mousemove", (e) => {
      const rect = parent.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      const isFlipped = ui.closest(".plugin__grid--flip");
      const baseY = isFlipped ? 3 : -3;

      ui.style.transform = `perspective(1200px) rotateY(${baseY + x * 4}deg) rotateX(${-y * 3}deg)`;
    });

    parent.addEventListener("mouseleave", () => {
      const isFlipped = ui.closest(".plugin__grid--flip");
      ui.style.transform = isFlipped
        ? "perspective(1200px) rotateY(3deg) rotateX(1deg)"
        : "perspective(1200px) rotateY(-3deg) rotateX(1deg)";
    });
  });

  /* ═══════════════════════════════════════════════════════
     i18n — EN / RU
     ═══════════════════════════════════════════════════════ */

  const I18N = {
    en: {
      skip: "To plugins",
      "hero.line": "Smart plugins for musicians.",
      "hero.cta1": "View plugins",
      "hero.ctaBuy": "Get free trial",
      "nav.account": "Account",
      "buy.eyebrow": "EASYBUNDLE",
      "buy.title": "Get a free trial",
      "buy.includes": "all five plugins, free for 3 months",
      "buy.first": "First name",
      "buy.last": "Last name",
      "buy.email": "Email",
      "buy.country": "Country",
      "buy.terms": "I agree to the license terms. One seat, personal use, no redistribution.",
      "buy.note": "Register and we'll email your account password and a license key valid for a free 3-month trial.",
      "buy.submit": "Get my free trial",
      "buy.done": "Registration complete. Check your email for the password and license key.",
      "buy.licenseLabel": "License key",
      "buy.openAccount": "Open account",
      "buy.sending": "Creating account & license…",
      "buy.errorServer": "Server offline — start: python3 server/app.py",
      "metroom.role": "Tempo calculator",
      "metroom.sound": "One-click delay calculator.",
      "metroom.pro1t": "Perfect timing:",
      "metroom.pro1d": "automatically reads the current BPM from your DAW.",
      "metroom.pro2t": "Fast workflow:",
      "metroom.pro2d": "calculate precise pre-delay and delay values instantly.",
      "metroom.pro3t": "One-click copy:",
      "metroom.pro3d": "press the button and paste into Valhalla or any other reverb.",
      "caesar.role": "Vocal compressor",
      "caesar.sound": "One-knob smart vocal compressor.",
      "caesar.pro1t": "Quick start:",
      "caesar.pro1d": "turn on GS, raise Compression — the vocal locks in place with makeup, air, and tone already balanced.",
      "caesar.pro2t": "Built-in intelligence:",
      "caesar.pro2d": "1176-style peak catch and LA-2A optical leveling with automatic attack, release, ratio, and knee — no timing math.",
      "caesar.pro3t": "Time saver:",
      "caesar.pro3d": "skip the usual compressor dance — get mix-ready vocal punch and control on demos and sessions in seconds.",
      "capsule.role": "Tempo-synced reverb",
      "capsule.sound": "Smart spatial reverb.",
      "capsule.pro1t": "Quick start:",
      "capsule.pro1d": "4 balanced presets for any task and instant sound improvement.",
      "capsule.pro2t": "Built-in intelligence:",
      "capsule.pro2d": "powered by Metroom technology — automatically calculates ideal pre-delay and decay.",
      "capsule.pro3t": "Time saver:",
      "capsule.pro3d": "forget manual calculations — get commercial-quality results on demos and live sessions in seconds.",
      "reflect.role": "Atmospheric vocal delay",
      "reflect.sound": "Unique hybrid of delay and space.",
      "reflect.pro1t": "New sonic character:",
      "reflect.pro1d": "blurs the line between textural delay and atmospheric reverb.",
      "reflect.pro2t": "Full sync:",
      "reflect.pro2d": "automatically locks to your session and sets ideal delay times.",
      "reflect.pro3t": "Experimental tool:",
      "reflect.pro3d": "ideal for creating unique spaces, ambient trails and unusual sound effects.",
      "slope.role": "Pitch & formant",
      "slope.sound": "Crystal-clear pitch shifter.",
      "slope.pro1t": "Honest sound:",
      "slope.pro1d": "shift pitch without dirt, metallic artifacts or quality loss.",
      "slope.pro2t": "Absolute clarity:",
      "slope.pro2d": "the algorithm preserves transients and source signal structure even at extreme shifts.",
    },
    ru: {
      skip: "К плагинам",
      "hero.line": "Интеллектуальные плагины для музыкантов.",
      "hero.cta1": "Смотреть плагины",
      "hero.ctaBuy": "Получить бесплатный триал",
      "nav.account": "Кабинет",
      "buy.eyebrow": "EASYBUNDLE",
      "buy.title": "Бесплатный триал",
      "buy.includes": "все пять плагинов, бесплатно на 3 месяца",
      "buy.first": "Имя",
      "buy.last": "Фамилия",
      "buy.email": "Email",
      "buy.country": "Страна",
      "buy.terms": "Согласен с условиями лицензии. Один seat, личное использование, без редистрибуции.",
      "buy.note": "Зарегистрируйся — пришлём на email пароль от кабинета и ключ лицензии, действующий 3 месяца бесплатно.",
      "buy.submit": "Получить бесплатный триал",
      "buy.done": "Регистрация завершена. Пароль и ключ отправлены на email.",
      "buy.licenseLabel": "Лицензионный ключ",
      "buy.openAccount": "Открыть кабинет",
      "buy.sending": "Создаём аккаунт и лицензию…",
      "buy.errorServer": "Сервер выключен — запусти: python3 server/app.py",
      "metroom.role": "Калькулятор темпа",
      "metroom.sound": "Калькулятор задержек в один клик.",
      "metroom.pro1t": "Идеальный тайминг:",
      "metroom.pro1d": "плагин автоматически считывает текущий BPM из вашей DAW.",
      "metroom.pro2t": "Быстрый рабочий процесс:",
      "metroom.pro2d": "рассчитывайте точные значения pre-delay и delay мгновенно.",
      "metroom.pro3t": "Копирование в один клик:",
      "metroom.pro3d": "просто нажмите кнопку и вставьте готовый параметр в Valhalla или любой другой ревербератор.",
      "caesar.role": "Вокальный компрессор",
      "caesar.sound": "Умный вокальный компрессор с одной ручкой.",
      "caesar.pro1t": "Быстрый старт:",
      "caesar.pro1d": "включи GS, подними Compression — вокал встает на место с уже сбалансированными makeup, air и тоном.",
      "caesar.pro2t": "Встроенный интеллект:",
      "caesar.pro2d": "пиковый ловец в стиле 1176 и оптическое усиление LA-2A с автоматическими attack, release, ratio и knee — никакой возни с таймингами.",
      "caesar.pro3t": "Экономия времени:",
      "caesar.pro3d": "забудьте про танцы с компрессором — получайте готовый к миксу вокальный панч и контроль на демо и сессиях за секунды.",
      "capsule.role": "Темпо-синхронный ревербератор",
      "capsule.sound": "Умный пространственный ревербератор.",
      "capsule.pro1t": "Быстрый старт:",
      "capsule.pro1d": "4 готовых сбалансированных пресета под любые задачи и мгновенное улучшение звука.",
      "capsule.pro2t": "Встроенный интеллект:",
      "capsule.pro2d": "плагин оснащён технологией Metroom — автоматически рассчитывает идеальные значения pre-delay и decay.",
      "capsule.pro3t": "Экономия времени:",
      "capsule.pro3d": "забудьте про рутинные расчёты — получайте коммерческий результат на демо-записях и живых сессиях за пару секунд.",
      "reflect.role": "Атмосферная вокальная задержка",
      "reflect.sound": "Уникальный гибрид задержки и пространства.",
      "reflect.pro1t": "Новый характер звука:",
      "reflect.pro1d": "размывает границы между текстурным дилеем и атмосферным ревербератором.",
      "reflect.pro2t": "Полная синхронизация:",
      "reflect.pro2d": "автоматически подстраивается под вашу сессию и настраивает идеальное время задержек.",
      "reflect.pro3t": "Экспериментальный инструмент:",
      "reflect.pro3d": "идеален для создания уникальных пространств, эмбиент-шлейфов и необычных звуковых эффектов.",
      "slope.role": "Питч и форманта",
      "slope.sound": "Кристально чистый питч-шифтер.",
      "slope.pro1t": "Честный звук:",
      "slope.pro1d": "меняйте высоту тона без грязи, металлических артефактов и потери качества.",
      "slope.pro2t": "Абсолютная чистота:",
      "slope.pro2d": "алгоритм сохраняет транзиенты и структуру исходного сигнала даже при экстремальном сдвиге.",
    },
  };

  const langSwitch = document.getElementById("langSwitch");
  const langButtons = document.querySelectorAll(".rail__langs .rail__lang");
  let currentLang = "en";

  function setLang(lang) {
    if (!I18N[lang]) return;
    currentLang = lang;
    document.documentElement.lang = lang;

    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (I18N[lang][key] !== undefined) {
        el.textContent = I18N[lang][key];
      }
    });

    document.querySelectorAll("#buyCountry option[data-en]").forEach((opt) => {
      opt.textContent = opt.getAttribute(`data-${lang}`) || opt.getAttribute("data-en");
    });

    langButtons.forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.lang === lang);
    });

    try { localStorage.setItem("easybundle-lang", lang); } catch (_) {}
  }

  function initLang() {
    let saved;
    try { saved = localStorage.getItem("easybundle-lang"); } catch (_) {}
    if (saved && I18N[saved]) {
      setLang(saved);
    } else if (navigator.language && navigator.language.startsWith("ru")) {
      setLang("ru");
    }
  }

  langButtons.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (isMobileLang()) {
        const st = chipState.get(langSwitchEl);
        if (st && !st.tapped) {
          // Collapsed chip: the active lang button covers it — tap opens the morph
          openMobileLang();
          return;
        }
        setLang(btn.dataset.lang);
        closeMobileLang();
        return;
      }
      setLang(btn.dataset.lang);
    });
  });

  // Mobile: tapping anywhere outside the lang chip closes it
  const langSwitchEl = document.getElementById("langSwitch");

  function openMobileLang() {
    if (!langSwitchEl || !isMobileLang()) return;
    // The chip stays in normal flex flow: it reserves its own space, so the
    // scroller never slides underneath it and the header doesn't shift.
    langSwitchEl.classList.add("is-open");
    const st = chipState.get(langSwitchEl);
    if (st) st.tapped = true;
  }

  function closeMobileLang() {
    if (!langSwitchEl) return;
    langSwitchEl.classList.remove("is-open");
    const st = chipState.get(langSwitchEl);
    if (st) st.tapped = false;
  }

  // Edge fade only where a button is actually cut off — a fully-visible
  // button is never dimmed. Mask is updated on scroll / resize / resize.
  const railMenu = document.getElementById("railMenu");
  function updateNavMask() {
    if (!railMenu) return;
    if (!isMobileLang()) {
      railMenu.style.webkitMaskImage = "";
      railMenu.style.maskImage = "";
      return;
    }
    const max = railMenu.scrollWidth - railMenu.clientWidth;
    if (max <= 0) {
      railMenu.style.webkitMaskImage = "";
      railMenu.style.maskImage = "";
      return;
    }
    const pad = 32;
    const left = railMenu.scrollLeft > 2;
    const right = railMenu.scrollLeft < max - 2;
    let mask = "";
    if (left && right) {
      mask = `linear-gradient(to right, transparent 0, #000 ${pad}px, #000 calc(100% - ${pad}px), transparent 100%)`;
    } else if (left) {
      mask = `linear-gradient(to right, transparent 0, #000 ${pad}px, #000 100%)`;
    } else if (right) {
      mask = `linear-gradient(to right, #000 0, #000 calc(100% - ${pad}px), transparent 100%)`;
    }
    railMenu.style.webkitMaskImage = mask;
    railMenu.style.maskImage = mask;
  }

  if (railMenu) {
    railMenu.addEventListener("scroll", updateNavMask, { passive: true });
    window.addEventListener("resize", updateNavMask);
    window.addEventListener("load", updateNavMask);
    document.fonts && document.fonts.ready && document.fonts.ready.then(updateNavMask);
    updateNavMask();
  }

  if (langSwitchEl) {
    document.addEventListener("pointerdown", (e) => {
      if (isMobileLang() && langSwitchEl.classList.contains("is-open") && !langSwitchEl.contains(e.target)) {
        closeMobileLang();
      }
    });
    window.addEventListener("resize", () => {
      if (!isMobileLang()) closeMobileLang();
    });
    window.addEventListener("scroll", () => {
      if (langSwitchEl.classList.contains("is-open")) closeMobileLang();
    }, { passive: true });
  }

  initLang();

  /* ═══════════════════════════════════════════════════════
     Registration — free 3-month trial
     ═══════════════════════════════════════════════════════ */
  const checkout = document.getElementById("checkout");
  const checkoutForm = document.getElementById("checkoutForm");
  const checkoutStatus = document.getElementById("checkoutStatus");
  const buyOpen = document.getElementById("buyOpen");

  function t(key) {
    return (I18N[currentLang] && I18N[currentLang][key]) || (I18N.en[key] || key);
  }

  function openCheckout() {
    if (!checkout) return;
    checkout.classList.add("is-open");
    checkout.classList.remove("is-done");
    checkout.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    const first = document.getElementById("buyFirst");
    if (first) first.focus();
  }

  function closeCheckout() {
    if (!checkout) return;
    checkout.classList.remove("is-open");
    checkout.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }

  if (buyOpen) buyOpen.addEventListener("click", openCheckout);

  document.querySelectorAll("[data-checkout-close]").forEach((el) => {
    el.addEventListener("click", closeCheckout);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && checkout && checkout.classList.contains("is-open")) {
      closeCheckout();
    }
  });

  if (checkoutForm) {
    checkoutForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = checkoutForm.querySelector(".checkout__submit");
      const fd = new FormData(checkoutForm);
      const payload = {
        first_name: String(fd.get("first_name") || "").trim(),
        last_name: String(fd.get("last_name") || "").trim(),
        email: String(fd.get("email") || "").trim(),
        country: String(fd.get("country") || "").trim(),
        terms: fd.get("terms") === "on",
      };

      if (!payload.first_name || !payload.last_name || !payload.email || !payload.country || !payload.terms) {
        checkoutStatus.textContent = currentLang === "ru"
          ? "Заполни обязательные поля и прими условия."
          : "Fill required fields and accept the terms.";
        checkoutStatus.className = "checkout__status is-error";
        return;
      }

      checkoutStatus.textContent = t("buy.sending");
      checkoutStatus.className = "checkout__status";
      if (submitBtn) submitBtn.disabled = true;

      try {
        const res = await fetch("/api/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          checkoutStatus.textContent = data.error || "Registration failed";
          checkoutStatus.className = "checkout__status is-error";
          if (submitBtn) submitBtn.disabled = false;
          return;
        }

        const licenseEl = document.getElementById("checkoutLicense");
        if (licenseEl) licenseEl.textContent = data.license_key;

        let msg = t("buy.done");
        if (data.email_delivery && data.email_delivery.method === "outbox") {
          msg += currentLang === "ru"
            ? ` Письмо также сохранено в Desktop/key/outbox.`
            : ` Email also saved to Desktop/key/outbox.`;
        }
        if (data.temp_password) {
          msg += currentLang === "ru"
            ? ` Временный пароль: ${data.temp_password}`
            : ` Temporary password: ${data.temp_password}`;
        }

        const doneP = document.querySelector("#checkoutDone [data-i18n='buy.done']");
        if (doneP) doneP.textContent = msg;

        checkout.classList.add("is-done");
        checkoutStatus.textContent = "";
      } catch (_) {
        checkoutStatus.textContent = t("buy.errorServer");
        checkoutStatus.className = "checkout__status is-error";
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
})();
