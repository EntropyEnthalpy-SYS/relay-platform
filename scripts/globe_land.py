"""Rebuild the overview globe's land dots in web/globe.js.

Input: Natural Earth 1:50m land polygons (public domain), for example
https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_land.geojson

Usage: python3 scripts/globe_land.py ne_50m_land.geojson

Rows run every STEP degrees of latitude; each row holds round(360*cos(lat)/STEP)
evenly spaced dots, so dots keep a similar spacing on the sphere. A dot is land
when its centre lies inside a land ring (even-odd rule). The script replaces
the `const LAND = ...;` line with per-row counts and the packed bits (row-major,
most significant bit first) as base64.
"""
import base64, bisect, json, math, pathlib, re, sys

STEP = 1.2
LAT_MIN, LAT_MAX = -58.0, 84.0

data = json.load(open(sys.argv[1], encoding='utf-8'))
rings = []
for feature in data['features']:
    geometry = feature['geometry']
    polygons = [geometry['coordinates']] if geometry['type'] == 'Polygon' else geometry['coordinates']
    for polygon in polygons:
        rings.extend(polygon)
edges = []
for ring in rings:
    for (x1, y1), (x2, y2) in zip(ring, ring[1:] + ring[:1]):
        if y1 != y2:
            edges.append((x1, y1, x2, y2))

counts, bits = [], []
rows = int(round((LAT_MAX - LAT_MIN) / STEP)) + 1
for r in range(rows):
    lat = LAT_MIN + r * STEP
    n = max(1, int(math.floor(360 * math.cos(math.radians(lat)) / STEP + 0.5)))
    crossings = sorted(x1 + (lat - y1) * (x2 - x1) / (y2 - y1) for x1, y1, x2, y2 in edges if (y1 <= lat < y2) or (y2 <= lat < y1))
    counts.append(n)
    for i in range(n):
        lon = -180 + (i + 0.5) * 360 / n
        bits.append(bisect.bisect_left(crossings, lon) % 2)

packed = bytearray((len(bits) + 7) // 8)
for i, bit in enumerate(bits):
    if bit:
        packed[i >> 3] |= 0x80 >> (i & 7)
line = "const LAND = { step: %s, latMin: %d, counts: '%s', bits: '%s' };" % (STEP, LAT_MIN, ','.join(map(str, counts)), base64.b64encode(bytes(packed)).decode())
target = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'globe.js'
source = target.read_text(encoding='utf-8')
updated, replaced = re.subn(r'^const LAND = .*;$', lambda _: line, source, count=1, flags=re.M)
assert replaced == 1, 'LAND line not found in web/globe.js'
target.write_text(updated, encoding='utf-8')
print(f'{sum(bits)} land dots of {len(bits)}')
