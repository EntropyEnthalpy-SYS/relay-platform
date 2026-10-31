// Dependency-free orthographic globe for the overview. Land dots are sampled
// every 1.2° from Natural Earth 1:50m land polygons (public domain), packed
// most-significant bit first, row by row from 58°S. See scripts/globe_land.py.
const LAND = { step: 1.2, latMin: -58, counts: '159,164,169,175,180,185,190,194,199,204,208,213,217,222,226,230,234,238,241,245,249,252,256,259,262,265,268,271,273,276,278,280,283,285,287,288,290,292,293,294,295,296,297,298,299,299,300,300,300,300,300,300,299,299,298,297,296,295,294,293,291,290,288,286,284,282,280,277,275,272,270,267,264,261,258,254,251,248,244,240,236,232,228,224,220,216,211,207,202,198,193,188,183,178,173,168,163,157,152,146,141,135,130,124,118,112,107,101,95,89,83,77,71,64,58,52,46,40,33', bits: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAAfgAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAAP4AAAAAAAAAAAAAAAAAAAAAgACAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAGAAIAAAAAAAAAAAH8AAAAAAAAAAAAAAAAAAAAAAgAAgAAAAAAAAAAA/4AAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAf/AAAAAAAAAAAAAAAAAAAAAB+AAAAAAAAAAAAAAAf/AAAAAAAAAAAAAAAAAAAAAB/AACAAAAAAAAAAAAH/wAAAAAAAAAAAAAAAAAAAAAH+AAIAAAAAAAAAAAAD/8AAAAAAAA+AAAAAAAAAAcAF/wAAAAAAAAAAAAAAAP/4AAAAAAAB/AAAAAAAAAAfgN/wAAAAAAAAAAAAAAAH//AAAAAAAAf4AAAAAAAAAD/z//gAAAAAAAAAAAAAAAP/+AAAAAAAA/8AAAAAAAAAD////wAAAAAAAAAAAAAAAD//wAAAAAAAP/gAAAAAAAAAP////AAAAAAAAAAAAAAAAH//wAAAAAAAf/gAAAAAAAAAP////AAAAAAAAAAAAAAAAB//8AAAAAAAH/8AAAAAAAAAB////8AAAAAAAAAAAAAAAAD//4AAAAAAAH/8AAAAAAAAAB////+AAAAAAAAAAAAAAAAA///AAAAAAAB//wGAAAAAAAAP////gAAAAAAAAAAAAAAAAD///AAAAAAAH//geAAAAAAAAf////AAAAAAAAAAAAAAAAAB///4AAAAAAD//wPAAAAAAAAH////AAQAAAAAAAAAAAAAAAf///AAAAAAA//+A8AAAAAAAAH///8ACAAAAAAAAAAAAAAAA////AAAAAAA//+A8AAAAAAAAAf//8AAAAAAAAAAAAAAAAAAP///wAAAAAAf//4PgAAAAAAAAD//+AAAAAAAAAAAAAAAAAAD////AAAAAAB///weAAAAAAAAAH/88AAAAAAAAAAAAAAAAAAP////AAAAAAD///4eAAAAAAAAAB/44AAAAAAAAAAAAAAAAAAf////gAAAAAA///+DAAAAAAAAAAd4OAAAAAAAAAAAAAAAAAAH////4AAAAAAH///wMAAAAAAAAAAPggAAAAAAAAAAAAAAAAAAf////4AAAAAAP///AQAAAAAAAAAAPhAAAAAAAAAAAAAAAAAAA/////4AAAAAAP///AAAAAAAAAAAAQBAAAAAAAAAAAAAAAAAAB/////8AAAAAAP///AAAAAAAAAAAEAADAAAAAAAAAAAAAAAAAA//////AAAAAAD///gAAAAAAAAADogAZgAAAAAAAAAAAAAAAAAP/////4AAAAAA///8AAAAAAAAA+AAAf4AAAAAAAAAAAAAAAAAD//////AAAAAAH///gAAAAAAAAGAAAA/gQAAAAAAAAAAAAAAAAP/////8AAAAAAP///gAAAAAAAAgAEAD+EAAAAAAAAAAAAAAAAAf/////gAAAAAA///+AAAAAAAADAAQA/4AAAAAAAAAAAAAAAAAAf////4AAAAAAD///+AAAAAAAAfj5QDfAAAAAAAAAAAAAAAAAAAf///fgAAAAAAD////gAAAAAAAuD5wjAAAAAAAAAAAAAAAAAAAAf///sAAAAAAAD////gAAAAAAAcH8ACAAAAAAAAAAAAAAAAAAAAf///wAAAAAAAD////wAAAAAABaH88gAAAAAAAAAAAAAAAAAAAAH///wAAAAAAAD////8AAAAAAA2B8AgAAAAAAAAAAAAAAAAAAAAH///gAAAAAAAD////+AAAAAABsA8AAAAAAAAAAAAAAAAAAAAAAH///gAAAAAAA3////+AAAAAAGYA8AAAAAAAAAAAAAAAAAAAAAAP//8AAAAAD/B/////+AAAAAAAwAYAAAAAAAAAAAAAAAAAAAAAAf/+AAAAAAP///////8AAABgACAAAgAAAAAAAAAAAAAAAAAAAAT//wAAAAAD////////wAAAMAQgAAeAAAAAAAAAAAAAAAAAAAAJv/4AAAAAA////////+AAAMAAIQABgAAAAAAAAAAAAAAAAAAAMB/IAAAAAAf////////AAAHAAEMABAAAAAAAAAAAAAAAAAAAAGAQAAAAAAAf///////AgAAHAAAfAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAB////////gAAAfAAF/ABAAAAAAAAAAAAAAAAAAAH4AAAAAAAAH///////3gAAB4AA/4AwAAAAAAAAAAAAAAAAAAD/AAAAAAAAB///////5/AAAfAAP+AIAAAAAAAAAAAAAAAAAAf4AAAAAAAAAf//////4/wAAfwBv8AMAAAAAAAAAAAAAAAAAD/4AAAAAAAAA///////z/4AB/gD/wAQAAAAAAAAAAAAAAAAA/DAA8AAAAAAH//////8f/gAP+A/4gAAAAAAAAAAAAAAAAAA/gwDAAAAAAAD//////8f/wAP/g/8QAAAAAAAAAAAAAAAAAA/AwGAAAAAAAH//////7//wDf/D/9AAAAAAAAAAAAAAAAAAH4APAAAAAAAA//////+f/+A//9//8EAAAAAAAAAAAAAAAAn8AAIAAAAAAA//////8//4B//////IAAAAAAAAAAAAAAAE/wAAAAAAAAAB//////P/mAf/////9AAAAAAAAAAAAAAABf8ACAAAAAAAA//////n/w///////8AAAAAAAAAAAAAAAE/4AMAAAAAAAA/////+/8f///////4AAAAAAAAAAAAAABf/ADAAAAAAAAH//////+f///////8AAAAAAAAAAAAAAC//sGAAAAAAAAP//////z////////wAAAAAAAAAAAAAAv///gAAAAAAAD///f///////////wAAAAAAAAAAAAAB////AAAAAAAAP//xwH/////////+BAAAAAAAAAAAAA////wAAAAAAAD/+AAD/////////8CAAAAAAAAAAAAH////wAAAAAAAP/wAAP/////////AaAAAAAAAAAAAH////8AAAAAAAA/wAAf////////8GPAAAAAAAAAAA/////AAAAAAABxcAC//v///////GBgAAAAAAAAAD/////AAAAAAAfgHGf/4///////hgIAAAAAAAAAB/////AAAAAAAfghM//4///////SAQAAAAAAAAAP////8AAAAAAH4I+H/+///////vgIAAAAAAAAAP////+AAAAAAP4mfmHh///////8AAAAAAAAAAH/////AAAAAAP4M/APH///////6GAAAAAAAAAf////5AAAAAAP2/wHj////////DgAAAAAAAA/////9gAAAAA///P8f///////5AAAAAAAAA/////9gAAAAB//+38////////gAAAAAAAAP/////QAAAAD/////////////AAAAAAAABf////YwAAAAf////////////oAAAAAAAF/////BAAAAA////////////6AAAAAAAH/////6AAAAP///////////+gAAAAAAD///8/+AAADc///////////4BAABAAD///+f9AAABsP//////////4GAACAAH///3/wAAAeAH////////8AOAABAA///4P4AAAAAo/////////AHAAAgB///gfgAAAGBl////////wDgAAQD//+B/AAAAQuf///////+AQAA6H//8B6AAAAD8P///////+iAAev//+A4BwAAHz////////8eAP////AyBwAAHn////////94B////yDB4AAD//////////yH///+ng8BwB7////////+b////4YPA4A9z////////j////Hj8AAP8/3/////4f/83zh/AAH8///////B/fOycH8AB8Av////+DwA7eD/AAMAP///8AAAfbwf8AABGv/7gAABw8D/AAAAf/gAAAGCAfwAAID4AAAAOsH/AACD8FAABFD/gAAgcAAAAGf4AAAQAAAF3+CAAgAAAW/AgAAAAB/wAAAAAN4AAAAAAAAAA=' };

// Common VPS locations: [code, Chinese name, English name, latitude, longitude].
export const cities = [
  ['HKG', '香港', 'Hong Kong', 22.32, 114.17], ['TYO', '东京', 'Tokyo', 35.68, 139.69], ['OSA', '大阪', 'Osaka', 34.69, 135.5],
  ['SEL', '首尔', 'Seoul', 37.57, 126.98], ['TPE', '台北', 'Taipei', 25.03, 121.57], ['SIN', '新加坡', 'Singapore', 1.35, 103.82],
  ['KUL', '吉隆坡', 'Kuala Lumpur', 3.14, 101.69], ['BKK', '曼谷', 'Bangkok', 13.76, 100.5], ['SGN', '胡志明市', 'Ho Chi Minh City', 10.82, 106.63],
  ['MNL', '马尼拉', 'Manila', 14.6, 120.98], ['JKT', '雅加达', 'Jakarta', -6.21, 106.85], ['BOM', '孟买', 'Mumbai', 19.08, 72.88],
  ['MAA', '金奈', 'Chennai', 13.08, 80.27], ['DXB', '迪拜', 'Dubai', 25.2, 55.27], ['TLV', '特拉维夫', 'Tel Aviv', 32.09, 34.78],
  ['SHA', '上海', 'Shanghai', 31.23, 121.47], ['BJS', '北京', 'Beijing', 39.9, 116.4], ['CAN', '广州', 'Guangzhou', 23.13, 113.26],
  ['SZX', '深圳', 'Shenzhen', 22.54, 114.06], ['HGH', '杭州', 'Hangzhou', 30.27, 120.16], ['CTU', '成都', 'Chengdu', 30.57, 104.07],
  ['SYD', '悉尼', 'Sydney', -33.87, 151.21], ['MEL', '墨尔本', 'Melbourne', -37.81, 144.96], ['AKL', '奥克兰', 'Auckland', -36.85, 174.76],
  ['LAX', '洛杉矶', 'Los Angeles', 34.05, -118.24], ['SJC', '圣何塞', 'San Jose', 37.34, -121.89], ['FMT', '弗里蒙特', 'Fremont', 37.55, -121.99],
  ['SFO', '旧金山', 'San Francisco', 37.77, -122.42], ['SEA', '西雅图', 'Seattle', 47.61, -122.33], ['LAS', '拉斯维加斯', 'Las Vegas', 36.17, -115.14],
  ['PHX', '凤凰城', 'Phoenix', 33.45, -112.07], ['DFW', '达拉斯', 'Dallas', 32.78, -96.8], ['CHI', '芝加哥', 'Chicago', 41.88, -87.63],
  ['IAD', '阿什本', 'Ashburn', 39.04, -77.49], ['NYC', '纽约', 'New York', 40.71, -74.01], ['ATL', '亚特兰大', 'Atlanta', 33.75, -84.39],
  ['MIA', '迈阿密', 'Miami', 25.76, -80.19], ['YYZ', '多伦多', 'Toronto', 43.65, -79.38], ['YUL', '蒙特利尔', 'Montreal', 45.5, -73.57],
  ['YVR', '温哥华', 'Vancouver', 49.28, -123.12], ['MEX', '墨西哥城', 'Mexico City', 19.43, -99.13], ['SAO', '圣保罗', 'São Paulo', -23.55, -46.63],
  ['LON', '伦敦', 'London', 51.51, -0.13], ['DUB', '都柏林', 'Dublin', 53.35, -6.26], ['AMS', '阿姆斯特丹', 'Amsterdam', 52.37, 4.9],
  ['FRA', '法兰克福', 'Frankfurt', 50.11, 8.68], ['PAR', '巴黎', 'Paris', 48.86, 2.35], ['MAD', '马德里', 'Madrid', 40.42, -3.7],
  ['MIL', '米兰', 'Milan', 45.46, 9.19], ['ZRH', '苏黎世', 'Zurich', 47.38, 8.54], ['STO', '斯德哥尔摩', 'Stockholm', 59.33, 18.07],
  ['HEL', '赫尔辛基', 'Helsinki', 60.17, 24.94], ['WAW', '华沙', 'Warsaw', 52.23, 21.01], ['IST', '伊斯坦布尔', 'Istanbul', 41.01, 28.98],
  ['MOW', '莫斯科', 'Moscow', 55.76, 37.62], ['JNB', '约翰内斯堡', 'Johannesburg', -26.2, 28.05],
];
// A saved location shows the city's name in the current language when its coordinates match a listed city.
export function cityFor(location) {
  if (!location) return null;
  return cities.find(c => Math.abs(c[3] * 1e6 - location.latitude_micros) < 5000 && Math.abs(c[4] * 1e6 - location.longitude_micros) < 5000) || null;
}

function landDots() {
  const counts = LAND.counts.split(',').map(Number), raw = atob(LAND.bits), dots = [];
  let bit = 0;
  counts.forEach((n, row) => {
    const lat = (LAND.latMin + row * LAND.step) * Math.PI / 180;
    for (let i = 0; i < n; i++, bit++) if (raw.charCodeAt(bit >> 3) & (0x80 >> (bit & 7))) dots.push(lat, (-180 + (i + 0.5) * 360 / n) * Math.PI / 180);
  });
  const xyz = new Float32Array(dots.length / 2 * 3);
  for (let i = 0; i < dots.length / 2; i++) {
    const lat = dots[i * 2], lon = dots[i * 2 + 1];
    xyz[i * 3] = Math.cos(lat) * Math.sin(lon); xyz[i * 3 + 1] = Math.sin(lat); xyz[i * 3 + 2] = Math.cos(lat) * Math.cos(lon);
  }
  return xyz;
}
const vector = (lat, lon) => { const a = lat * Math.PI / 180, b = lon * Math.PI / 180; return [Math.cos(a) * Math.sin(b), Math.sin(a), Math.cos(a) * Math.cos(b)]; };
const wrap = angle => Math.atan2(Math.sin(angle), Math.cos(angle));
// Canvas gradients fade through transparent black unless the end stop keeps the colour.
function fade(color, alpha) {
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color)?.[1]; if (!hex) return color;
  const full = hex.length === 3 ? [...hex].map(c => c + c).join('') : hex;
  return `rgba(${parseInt(full.slice(0, 2), 16)}, ${parseInt(full.slice(2, 4), 16)}, ${parseInt(full.slice(4, 6), 16)}, ${alpha})`;
}

// markers: [{ id, name, lat, lon, status: up|partial|down|idle, detail }]
// links: [{ from, to, state: up|partial|down|unknown }] between marker ids.
export function createGlobe({ label, onSelect }) {
  const box = document.createElement('div'), canvas = document.createElement('canvas'), tip = document.createElement('div');
  box.className = 'globe'; tip.className = 'globe-tip hidden'; canvas.setAttribute('role', 'img'); canvas.setAttribute('aria-label', label);
  box.append(canvas, tip);
  const context = canvas.getContext('2d'), dots = landDots(), motion = matchMedia('(prefers-reduced-motion: reduce)');
  let markers = [], links = [], hits = [], colors = null, width = 0, height = 0, frame = 0, last = 0, colorAge = 0;
  let yaw = -1.9, pitch = 0.35, target = null, drag = null, idleUntil = 0, hover = null, selected = null;
  function readColors() {
    const css = getComputedStyle(document.documentElement), v = name => css.getPropertyValue(name).trim();
    colors = { surface: v('--surface'), surface2: v('--surface-2'), line: v('--line-strong'), text: v('--text'), muted: v('--muted'), accent: v('--accent'), soft: v('--accent-soft'),
      up: v('--green'), partial: v('--amber'), down: v('--red'), idle: v('--muted'), unknown: v('--muted'), font: getComputedStyle(document.body).fontFamily };
  }
  let cosYaw = 1, sinYaw = 0, cosPitch = 1, sinPitch = 0;
  function rotate(x, y, z) {
    const x1 = x * cosYaw + z * sinYaw, z1 = z * cosYaw - x * sinYaw;
    return [x1, y * cosPitch - z1 * sinPitch, y * sinPitch + z1 * cosPitch];
  }
  function draw(now) {
    if (!colors || now - colorAge > 1000) { readColors(); colorAge = now; }
    cosYaw = Math.cos(yaw); sinYaw = Math.sin(yaw); cosPitch = Math.cos(pitch); sinPitch = Math.sin(pitch);
    const ratio = devicePixelRatio || 1, w = width, h = height, r = Math.min(w, h) / 2 - 34, cx = w / 2, cy = h / 2;
    // Zoom or a move to another screen changes the ratio without resizing the box.
    if (canvas.width !== Math.round(w * ratio) || canvas.height !== Math.round(h * ratio)) { canvas.width = Math.round(w * ratio); canvas.height = Math.round(h * ratio); }
    context.setTransform(ratio, 0, 0, ratio, 0, 0); context.clearRect(0, 0, w, h);
    if (r < 40) return;
    const glow = context.createRadialGradient(cx, cy, r * 0.96, cx, cy, r * 1.25); glow.addColorStop(0, fade(colors.accent, 0.16)); glow.addColorStop(1, fade(colors.accent, 0));
    context.fillStyle = glow; context.fillRect(0, 0, w, h);
    const shade = context.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.1, cx, cy, r);
    shade.addColorStop(0, colors.surface); shade.addColorStop(1, colors.surface2);
    context.beginPath(); context.arc(cx, cy, r, 0, Math.PI * 2); context.fillStyle = shade; context.fill();
    context.lineWidth = 1; context.strokeStyle = colors.line; context.stroke();
    // Faint graticule every 30°, front hemisphere only.
    context.save(); context.globalAlpha = 0.28; context.strokeStyle = colors.line; context.beginPath();
    const line = points => { let pen = false; for (const [lat, lon] of points) { const [x, y, z] = rotate(...vector(lat, lon)); if (z < 0) { pen = false; continue; } const px = cx + x * r, py = cy - y * r; if (pen) context.lineTo(px, py); else context.moveTo(px, py); pen = true; } };
    for (let lon = -180; lon < 180; lon += 30) line(Array.from({ length: 37 }, (_, i) => [-90 + i * 5, lon]));
    for (let lat = -60; lat <= 60; lat += 30) line(Array.from({ length: 73 }, (_, i) => [lat, -180 + i * 5]));
    context.stroke(); context.restore();
    // Land dots, dimmer and smaller towards the rim.
    const size = Math.max(1.5, r / 150), bands = [new Path2D(), new Path2D(), new Path2D()];
    for (let i = 0; i < dots.length; i += 3) {
      const x = dots[i], y = dots[i + 1], z = dots[i + 2], x1 = x * cosYaw + z * sinYaw, z1 = z * cosYaw - x * sinYaw, depth = y * sinPitch + z1 * cosPitch;
      if (depth < 0) continue;
      bands[depth < 0.35 ? 0 : depth < 0.7 ? 1 : 2].rect(cx + x1 * r - size / 2, cy - (y * cosPitch - z1 * sinPitch) * r - size / 2, size, size);
    }
    context.fillStyle = colors.text;
    bands.forEach((band, i) => { context.globalAlpha = [0.2, 0.36, 0.55][i]; context.fill(band); });
    context.globalAlpha = 1;
    const byId = new Map(markers.map(m => [m.id, m])), animate = !motion.matches, phase = (now % 2400) / 2400;
    // Raised great-circle arcs; a point behind the sphere is hidden.
    for (const [index, link] of links.entries()) {
      const a = byId.get(link.from), b = byId.get(link.to); if (!a || !b) continue;
      const va = vector(a.lat, a.lon), vb = vector(b.lat, b.lon), dot = Math.max(-1, Math.min(1, va[0] * vb[0] + va[1] * vb[1] + va[2] * vb[2])), angle = Math.acos(dot);
      if (angle < 1e-4) continue;
      const lift = 0.06 + 0.22 * angle / Math.PI, steps = 64, path = [];
      for (let i = 0; i <= steps; i++) {
        const t = i / steps, s = Math.sin(angle), k1 = Math.sin((1 - t) * angle) / s, k2 = Math.sin(t * angle) / s, raised = 1 + lift * Math.sin(Math.PI * t);
        const [x, y, z] = rotate((va[0] * k1 + vb[0] * k2) * raised, (va[1] * k1 + vb[1] * k2) * raised, (va[2] * k1 + vb[2] * k2) * raised);
        path.push([cx + x * r, cy - y * r, z >= 0 || x * x + y * y > 1]);
      }
      const color = colors[link.state] || colors.unknown;
      context.strokeStyle = color; context.lineWidth = link.state === 'unknown' ? 1.2 : 1.8; context.setLineDash(link.state === 'up' ? [] : [5, 5]); context.globalAlpha = 0.9;
      context.beginPath(); let pen = false;
      for (const [x, y, visible] of path) { if (!visible) { pen = false; continue; } if (pen) context.lineTo(x, y); else context.moveTo(x, y); pen = true; }
      context.stroke(); context.setLineDash([]);
      if (animate && link.state !== 'down') {
        const at = path[Math.round(((phase + index * 0.37) % 1) * steps)];
        if (at[2]) { context.globalAlpha = 1; context.fillStyle = color; context.beginPath(); context.arc(at[0], at[1], 2.6, 0, Math.PI * 2); context.fill(); }
      }
      context.globalAlpha = 1;
    }
    hits = [];
    context.font = `600 12px ${colors.font}`; context.textBaseline = 'middle';
    for (const m of markers) {
      const [x, y, z] = rotate(...vector(m.lat, m.lon)); if (z < 0.02) continue;
      const px = cx + x * r, py = cy - y * r, color = colors[m.status] || colors.idle, focus = m.id === hover || m.id === selected;
      if (animate && (m.status === 'up' || m.status === 'down')) {
        context.globalAlpha = 0.5 * (1 - phase); context.strokeStyle = color; context.lineWidth = 1.5;
        context.beginPath(); context.arc(px, py, 5 + phase * 12, 0, Math.PI * 2); context.stroke(); context.globalAlpha = 1;
      }
      context.beginPath(); context.arc(px, py, focus ? 7 : 5.5, 0, Math.PI * 2); context.fillStyle = color; context.fill();
      context.lineWidth = 2; context.strokeStyle = colors.surface; context.stroke();
      // Labels that would run past the canvas edge sit on the marker's left instead.
      const left = px + 11 + context.measureText(m.name).width > w - 4, tx = left ? px - 11 : px + 11;
      context.textAlign = left ? 'right' : 'left';
      context.lineWidth = 4; context.strokeStyle = colors.surface; context.strokeText(m.name, tx, py); context.fillStyle = colors.text; context.fillText(m.name, tx, py);
      hits.push({ id: m.id, x: px, y: py });
    }
  }
  function loop(now) {
    frame = 0;
    if (!canvas.isConnected || document.hidden) return;
    const dt = last ? Math.min(64, now - last) : 16; last = now;
    let moving = !!drag;
    if (target) {
      const dy = wrap(target[0] - yaw), dp = target[1] - pitch;
      yaw += dy * 0.12; pitch += dp * 0.12;
      if (Math.abs(dy) < 0.002 && Math.abs(dp) < 0.002) target = null;
      moving = true;
    } else if (!drag && !motion.matches && now > idleUntil) { yaw += dt * 0.00009; moving = true; }
    draw(now);
    if (moving || !motion.matches) frame = requestAnimationFrame(loop);
  }
  function start() { if (!frame && canvas.isConnected && !document.hidden) { last = 0; frame = requestAnimationFrame(loop); } }
  new ResizeObserver(() => {
    width = box.clientWidth; height = box.clientHeight; draw(performance.now()); start();
  }).observe(box);
  document.addEventListener('visibilitychange', start);
  const pick = event => { const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top; return hits.find(h => (h.x - x) ** 2 + (h.y - y) ** 2 < 144) || null; };
  canvas.addEventListener('pointerdown', event => { drag = { x: event.clientX, y: event.clientY, yaw, pitch, moved: false }; canvas.setPointerCapture(event.pointerId); target = null; start(); });
  canvas.addEventListener('pointermove', event => {
    if (drag) {
      const scale = 1 / Math.max(120, Math.min(width, height) / 2), dx = event.clientX - drag.x, dy = event.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      yaw = drag.yaw + dx * scale; pitch = Math.max(-1.2, Math.min(1.2, drag.pitch + dy * scale)); return;
    }
    const hit = pick(event), next = hit?.id || null; canvas.classList.toggle('pointer', !!hit);
    if (next !== hover) { hover = next; showTip(hit); if (motion.matches) draw(performance.now()); }
  });
  canvas.addEventListener('pointerleave', () => { if (!drag) { hover = null; showTip(null); } });
  const release = event => {
    if (!drag) return;
    const clicked = !drag.moved && pick(event); drag = null; idleUntil = performance.now() + 4000;
    if (clicked) { select(clicked.id); onSelect?.(clicked.id); }
  };
  canvas.addEventListener('pointerup', release); canvas.addEventListener('pointercancel', release);
  function showTip(hit) {
    const marker = hit && markers.find(m => m.id === hit.id);
    tip.classList.toggle('hidden', !marker); if (!marker) return;
    tip.replaceChildren(Object.assign(document.createElement('strong'), { textContent: marker.name }), Object.assign(document.createElement('span'), { textContent: marker.detail || '' }));
    tip.style.left = `${Math.round(hit.x + 14)}px`; tip.style.top = `${Math.round(hit.y + 14)}px`;
  }
  function select(id) {
    selected = id; const m = markers.find(item => item.id === id);
    if (m) { target = [-m.lon * Math.PI / 180, m.lat * Math.PI / 180]; idleUntil = performance.now() + 6000; }
    start();
  }
  let centred = false;
  return {
    element: box,
    update(nextMarkers, nextLinks) {
      markers = nextMarkers; links = nextLinks;
      if (!centred && markers.length) {
        // Start facing the average node position; a drag or selection takes over afterwards.
        const sum = markers.reduce((s, m) => { const v = vector(m.lat, m.lon); return [s[0] + v[0], s[1] + v[1], s[2] + v[2]]; }, [0, 0, 0]);
        yaw = -Math.atan2(sum[0], sum[2]); pitch = Math.max(-0.8, Math.min(0.8, Math.atan2(sum[1], Math.hypot(sum[0], sum[2])))); centred = true;
      }
      draw(performance.now()); start();
    },
    select,
  };
}
