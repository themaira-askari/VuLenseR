/* =====================================================================
   NEW FILE: login-lamp.js
   Sirf VISUAL effects (lamp, themes, fireflies, parallax, sound).
   Ye file auth.js ke koi function, form id, ya API call ko touch nahi karti.
   Sirf #authShell ke andar naye decorative elements add karti hai.
   ===================================================================== */
(function () {
    const shell = document.getElementById("authShell");
    if (!shell) return;                       // login screen nahi hai to kuch mat karo

    // Lamp ki 4 themes: Cyan (default) -> Indigo -> Violet -> Lights Out
  const THEMES = [
    { c: "#38BDF8", r: "56,189,248",  bg: "#04131c", on: 1 },
    { c: "#FFC857", r: "255,200,87",  bg: "#140f04", on: 1 },
    { c: "#43F2E1", r: "67,242,225",  bg: "#030d0c", on: 1 },
    { c: "#555a6b", r: "85,90,107",   bg: "#0b0c10", on: 0 }
];
    let idx = 0, soundOn = true, audioCtx = null;

    function applyTheme(i) {
        const t = THEMES[i];
        shell.style.setProperty("--c", t.c);
        shell.style.setProperty("--c-rgb", t.r);
        shell.style.setProperty("--lbg", t.bg);
        shell.style.setProperty("--on", t.on);
    }

    function beep(freq, dur) {                // chhoti si click awaaz (sirf effect)
        if (!soundOn) return;
        try {
            audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
            const o = audioCtx.createOscillator(), g = audioCtx.createGain();
            o.type = "square"; o.frequency.value = freq;
            g.gain.setValueAtTime(0.08, audioCtx.currentTime);
            g.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + dur);
            o.connect(g); g.connect(audioCtx.destination);
            o.start(); o.stop(audioCtx.currentTime + dur);
        } catch (e) { /* audio na chale to koi masla nahi */ }
    }

    // ---- Decorative elements bana kar shell mein daalna ----
    const glow = document.createElement("div");
    glow.className = "lm-glow";

    const lampWrap = document.createElement("div");
    lampWrap.className = "lm-lampwrap";
    lampWrap.setAttribute("aria-hidden", "true");
    lampWrap.innerHTML =
        '<div class="lm-cone"></div>' +
        '<div class="lm-lamp">' +
          '<div class="lm-shade"></div><div class="lm-bulb"></div>' +
          '<div class="lm-pole"></div><div class="lm-base"></div>' +
          '<div class="lm-cord" id="lmCord"><div class="lm-knob" id="lmKnob"></div></div>' +
        '</div>' +
        '<div class="lm-hint">Pull the cord down to change the theme ↓</div>';

    const sndBtn = document.createElement("button");
    sndBtn.type = "button";                    // type=button: kisi form ko submit nahi karega
    sndBtn.className = "lm-snd";
    sndBtn.setAttribute("aria-label", "Toggle sound");
    sndBtn.textContent = "🔊";
    sndBtn.addEventListener("click", () => {
        soundOn = !soundOn;
        sndBtn.textContent = soundOn ? "🔊" : "🔇";
    });

    // Fireflies
    for (let i = 0; i < 26; i++) {
        const f = document.createElement("div");
        f.className = "lm-fly";
        f.style.left = Math.random() * 100 + "%";
        f.style.top = Math.random() * 100 + "%";
        f.style.setProperty("--dx", (Math.random() * 120 - 60) + "px");
        f.style.setProperty("--dy", (Math.random() * -140) + "px");
        f.style.animationDuration = (5 + Math.random() * 7) + "s";
        f.style.animationDelay = (-Math.random() * 8) + "s";
        shell.appendChild(f);
    }

    shell.prepend(lampWrap);                   // lamp left side par
    shell.prepend(glow);
    shell.appendChild(sndBtn);
    applyTheme(0);

    // ---- Rassi kheenchna (drag) ----
    const cord = document.getElementById("lmCord");
    const knob = document.getElementById("lmKnob");
    let startY = null;
    knob.addEventListener("pointerdown", e => {
        startY = e.clientY; knob.setPointerCapture(e.pointerId); cord.classList.add("drag");
    });
    knob.addEventListener("pointermove", e => {
        if (startY === null) return;
        const d = Math.max(0, Math.min(70, e.clientY - startY));
        cord.style.height = (70 + d) + "px";
    });
    function release() {
        if (startY === null) return;
        const pulled = parseFloat(cord.style.height || 70) - 70;
        startY = null; cord.classList.remove("drag"); cord.style.height = "70px";
        if (pulled > 25) {                     // kaafi kheencha to theme badlo
            idx = (idx + 1) % THEMES.length;
            applyTheme(idx);
            beep(idx === 3 ? 160 : 520, 0.12);
        }
    }
    knob.addEventListener("pointerup", release);
    knob.addEventListener("pointercancel", release);

    // ---- Mouse parallax ----
    window.addEventListener("mousemove", e => {
        const x = (e.clientX / innerWidth - 0.5) * 16;
        const y = (e.clientY / innerHeight - 0.5) * 10;
        // FIX: parallax ab sirf lamp par (wrapper ka mobile scale override nahi hota)
        lampWrap.querySelector(".lm-lamp").style.transform = "translate(" + x + "px," + y + "px)";
    });
})();
