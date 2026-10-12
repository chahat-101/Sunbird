// Decorative 1-bit ordered dither on a WebGL1 canvas. The page never depends on it:
// without WebGL, or if the shader fails, the container keeps its CSS fallback.
(function () {
  'use strict';
  const PX = 3;        // dither cell, CSS pixels
  const SPEED = 0.6;   // wave time scale
  const FPS = 30;
  const MAX_DPR = 2;
  const STILL_TIME = 7.3;

  const VERT = 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
  const FRAG = `
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
uniform vec2 res;
uniform float cell, time, mode;
uniform vec3 hi, lo;
uniform sampler2D img;
uniform vec4 rect;
uniform float bg;

float bayer8(vec2 c) {
  c = mod(c, 8.0);
  float v = 0.0;
  for (int k = 0; k < 3; k++) {
    vec2 b = mod(floor(c / exp2(float(k))), 2.0);
    v += (2.0 * abs(b.x - b.y) + b.y) * exp2(float(4 - 2 * k));
  }
  return (v + 0.5) / 64.0;
}

float wave(vec2 p, float t) {
  float bend = 1.6 * sin(p.y * 2.1 - t * 0.7) + 0.6 * sin(p.x * 0.9 + t * 0.3);
  float a = sin((p.x + p.y * 0.4) * 4.2 + bend + t);
  float b = 0.6 + 0.4 * sin(p.x * 1.1 - p.y * 0.8 - t * 0.45);
  return 0.5 + 0.42 * a * b;
}

float photo(vec2 uv, float t) {
  uv.x += 0.004 * sin(uv.y * 21.0 + t);
  uv.y += 0.003 * sin(uv.x * 17.0 - t * 0.7);
  vec2 q = (uv - rect.xy) / rect.zw;
  float edge = smoothstep(0.0, 0.18, q.x) * smoothstep(0.0, 0.02, min(q.y, 1.0 - q.y)) * step(q.x, 1.0);
  float l = dot(texture2D(img, vec2(clamp(q.x, 0.0, 1.0), 1.0 - clamp(q.y, 0.0, 1.0))).rgb, vec3(0.299, 0.587, 0.114));
  l = smoothstep(0.28, 0.82, l);
  return mix(bg, l, edge);
}

void main() {
  vec2 c = floor(gl_FragCoord.xy / cell);
  vec2 centre = (c + 0.5) * cell;
  float v = mode < 0.5 ? wave(centre / res.y * 1.7, time) : photo(centre / res, time);
  gl_FragColor = vec4(v > bayer8(c) ? hi : lo, 1.0);
}`;

  const still = matchMedia('(prefers-reduced-motion: reduce)');
  const dark = matchMedia('(prefers-color-scheme: dark)');

  function rgb(value) {
    const m = value.match(/[\d.]+/g);
    return m ? [m[0] / 255, m[1] / 255, m[2] / 255] : [0, 0, 0];
  }

  function compile(gl, type, source) {
    const s = gl.createShader(type);
    gl.shaderSource(s, source);
    gl.compileShader(s);
    return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
  }

  function start(box) {
    const canvas = box.querySelector('canvas');
    let gl = null;
    try { gl = canvas.getContext('webgl', { antialias: false, alpha: false, preserveDrawingBuffer: true }); } catch (_) { /* none */ }
    if (!gl) return false;
    const vs = compile(gl, gl.VERTEX_SHADER, VERT);
    const fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return false;
    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const at = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(at);
    gl.vertexAttribPointer(at, 2, gl.FLOAT, false, 0, 0);
    const u = {};
    for (const name of ['res', 'cell', 'time', 'mode', 'hi', 'lo', 'img', 'rect', 'bg']) u[name] = gl.getUniformLocation(prog, name);

    const isPhoto = box.dataset.dither === 'photo';
    const fixed = 'ditherStill' in box.dataset;
    let image = null;
    gl.uniform1f(u.mode, isPhoto ? 1 : 0);
    gl.uniform1f(u.bg, Number(box.dataset.ditherBg || 0.62));

    let width = 0;
    let height = 0;
    let visible = true;
    let running = false;
    let last = 0;
    let elapsed = 0;

    function colours() {
      const style = getComputedStyle(canvas);
      gl.uniform3fv(u.hi, rgb(style.backgroundColor));
      gl.uniform3fv(u.lo, rgb(style.color));
    }

    function layout() {
      const dpr = Math.min(devicePixelRatio || 1, MAX_DPR);
      const r = box.getBoundingClientRect();
      width = Math.max(1, Math.round(r.width * dpr));
      height = Math.max(1, Math.round(r.height * dpr));
      canvas.width = width;
      canvas.height = height;
      gl.viewport(0, 0, width, height);
      gl.uniform2f(u.res, width, height);
      gl.uniform1f(u.cell, Math.max(1, Math.round(PX * dpr)));
      if (image) {
        const w = (image.naturalWidth / image.naturalHeight) * (height / width);
        gl.uniform4f(u.rect, w <= 1 ? 1 - w : (1 - w) * 0.35, 0, w, 1);
      }
    }

    function draw() {
      gl.uniform1f(u.time, (still.matches || fixed ? STILL_TIME : elapsed * SPEED) % 6283.0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }

    const busy = () => document.querySelector('.status[data-state="busy"]') !== null;
    const wanted = () => !fixed && visible && !document.hidden && !still.matches && !busy();

    function frame(now) {
      if (!wanted()) { running = false; return; }
      const step = now - last;
      if (step >= 1000 / FPS - 2) {
        elapsed += Math.min(step, 100) / 1000;
        last = now;
        draw();
      }
      requestAnimationFrame(frame);
    }

    function wake() {
      if (running || !wanted()) return;
      running = true;
      last = performance.now();
      requestAnimationFrame(frame);
    }

    function redraw() {
      colours();
      draw();
      wake();
    }

    new ResizeObserver(() => { layout(); draw(); }).observe(box);
    new IntersectionObserver((entries) => {
      visible = entries[entries.length - 1].isIntersecting;
      wake();
    }).observe(box);
    document.addEventListener('visibilitychange', wake);
    new MutationObserver(redraw).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    new MutationObserver(wake).observe(document.body, { subtree: true, attributes: true, attributeFilter: ['data-state'] });
    dark.addEventListener('change', redraw);
    still.addEventListener('change', redraw);

    layout();
    colours();
    if (isPhoto) {
      const tex = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, 1, 1, 0, gl.RGB, gl.UNSIGNED_BYTE, new Uint8Array([160, 160, 150]));
      for (const [k, v] of [[gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE], [gl.TEXTURE_MIN_FILTER, gl.LINEAR], [gl.TEXTURE_MAG_FILTER, gl.LINEAR]]) {
        gl.texParameteri(gl.TEXTURE_2D, k, v);
      }
      gl.uniform1i(u.img, 0);
      const pic = new Image();
      pic.onload = () => {
        image = pic;
        gl.bindTexture(gl.TEXTURE_2D, tex);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, pic);
        layout();
        draw();
      };
      pic.src = box.dataset.ditherSrc;
    }
    draw();
    wake();
    return true;
  }

  function init() {
    for (const box of document.querySelectorAll('[data-dither]')) {
      if (box.getClientRects().length === 0) continue;
      let ok = false;
      try { ok = start(box); } catch (_) { ok = false; }
      box.dataset.ditherPath = ok ? 'webgl' : 'static';
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
