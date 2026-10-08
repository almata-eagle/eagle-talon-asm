// Builds the two static geography files the SOC dashboard uses:
//   frontend/world-110m.json       country outlines as SVG paths (already projected)
//   backend/soc_geo_countries.json  country names/aliases (EN, JA) → ISO code + centroid
//
// Run it only when the map data should change; the outputs are committed, so
// nothing is fetched at runtime and the dashboard works offline.
//
//   mkdir /tmp/geo && cd /tmp/geo && npm init -y
//   npm install world-atlas@2.0.2 d3-geo@3.1.1 topojson-client@3.1.0 i18n-iso-countries@7.14.0
//   NODE_PATH=/tmp/geo/node_modules node tools/build-world-map.js
//
// Sources: Natural Earth 1:110m (public domain) via world-atlas (ISC);
// country names from i18n-iso-countries (MIT).
"use strict";
const fs = require("fs");
const path = require("path");
const d3 = require("d3-geo");
const topojson = require("topojson-client");
const iso = require("i18n-iso-countries");
const world = require("world-atlas/countries-110m.json");

const ROOT = path.join(__dirname, "..");
const W = 1000;

// Natural Earth 1, fitted to the full sphere at width W. The frontend
// re-implements the same forward formula (naturalEarth1Raw) with these numbers.
const projection = d3.geoNaturalEarth1().fitWidth(W, { type: "Sphere" }).precision(0.2);
const k = projection.scale();
const [tx, ty] = projection.translate();
const pathGen = d3.geoPath(projection);

const fc = topojson.feature(world, world.objects.countries);
const MANUAL_ISO = { "Kosovo": "XK", "N. Cyprus": null, "Somaliland": null };

function round(d) { return d.replace(/-?\d+\.\d+/g, (n) => (Math.round(parseFloat(n) * 10) / 10).toString()); }

// Centroid of the largest polygon, so France sits in Europe and the US in the
// lower 48 rather than somewhere pulled by overseas territories.
function mainCentroid(f) {
  const g = f.geometry;
  if (g.type === "Polygon") return d3.geoCentroid(f);
  let best = null, bestA = -1;
  for (const coords of g.coordinates) {
    const p = { type: "Feature", geometry: { type: "Polygon", coordinates: coords } };
    const a = d3.geoArea(p);
    if (a > bestA) { bestA = a; best = p; }
  }
  return d3.geoCentroid(best);
}

const shapes = [];
const centroids = {};
let ymin = Infinity, ymax = -Infinity;
for (const f of fc.features) {
  const name = f.properties.name;
  if (f.id === "010") continue; // Antarctica: no traffic, lots of pixels
  const iso2 = name in MANUAL_ISO ? MANUAL_ISO[name] : (iso.numericToAlpha2(f.id) || null);
  const [[, y0], [, y1]] = pathGen.bounds(f);
  ymin = Math.min(ymin, y0); ymax = Math.max(ymax, y1);
  shapes.push({ iso2, name, d: round(pathGen(f)) });
  if (iso2 && !centroids[iso2]) {
    const [lon, lat] = mainCentroid(f);
    centroids[iso2] = [Math.round(lat * 100) / 100, Math.round(lon * 100) / 100];
  }
}

// Countries too small for the 1:110m outlines but common in traffic logs.
const SMALL = {
  SG: [1.35, 103.82], HK: [22.32, 114.17], MO: [22.2, 113.55], BH: [26.07, 50.55], MT: [35.94, 14.38],
  LU: [49.82, 6.13], MC: [43.74, 7.42], AD: [42.51, 1.52], LI: [47.17, 9.56], SM: [43.94, 12.46],
  VA: [41.9, 12.45], GI: [36.14, -5.35], SC: [-4.68, 55.49], MU: [-20.35, 57.55], MV: [3.2, 73.22],
  BB: [13.19, -59.54], AG: [17.06, -61.8], DM: [15.41, -61.37], GD: [12.12, -61.68], KN: [17.36, -62.78],
  LC: [13.91, -60.98], VC: [12.98, -61.29], BM: [32.32, -64.76], KY: [19.31, -81.25], VG: [18.42, -64.64],
  VI: [18.34, -64.9], AW: [12.52, -69.97], CW: [12.17, -68.98], SX: [18.04, -63.05], JE: [49.21, -2.13],
  GG: [49.45, -2.58], IM: [54.24, -4.55], FO: [61.89, -6.91], PF: [-17.68, -149.41], GU: [13.44, 144.79],
  MP: [15.1, 145.67], AS: [-14.27, -170.13], WS: [-13.76, -172.1], TO: [-21.18, -175.2], KI: [1.87, -157.36],
  MH: [7.13, 171.18], FM: [6.89, 158.22], PW: [7.51, 134.58], NR: [-0.52, 166.93], TV: [-7.11, 177.65],
  CV: [16.0, -24.01], ST: [0.19, 6.61], KM: [-11.88, 43.87], RE: [-21.12, 55.54], YT: [-12.83, 45.17],
  MQ: [14.64, -61.02], GP: [16.27, -61.55], GF: [3.93, -53.13], PR: [18.22, -66.59], CK: [-21.24, -159.78],
  NU: [-19.05, -169.87], TK: [-9.2, -171.85], WF: [-13.77, -177.16], NC: [-20.9, 165.62], AI: [18.22, -63.07],
  MS: [16.74, -62.19], TC: [21.69, -71.8], BL: [17.9, -62.83], MF: [18.08, -63.05], PM: [46.94, -56.27],
  AX: [60.18, 19.92], SJ: [77.55, 23.67], IO: [-6.34, 71.88], CX: [-10.45, 105.69], CC: [-12.16, 96.87],
  NF: [-29.04, 167.95], PN: [-24.7, -127.44], SH: [-24.14, -10.03], BV: [-54.42, 3.41], HM: [-53.08, 73.5],
  GS: [-54.43, -36.59], TF: [-49.28, 69.35], UM: [19.28, 166.65], BQ: [12.18, -68.24], XK: [42.6, 20.9],
};
for (const [c, ll] of Object.entries(SMALL)) if (!centroids[c]) centroids[c] = ll;

// Names FortiGate and other sensors use that the ISO list doesn't.
const EXTRA_ALIASES = {
  VN: ["Viet Nam"], KR: ["Korea, South", "Korea"], KP: ["Korea, North", "Korea, Democratic People's Republic of"],
  US: ["United States"], GB: ["UK", "Great Britain", "England"], RU: ["Russia"], IR: ["Iran, Islamic Republic of", "Iran"],
  SY: ["Syrian Arab Republic"], LA: ["Lao People's Democratic Republic", "Laos"], MD: ["Moldova, Republic of"],
  TZ: ["Tanzania, United Republic of"], VE: ["Venezuela, Bolivarian Republic of"], BO: ["Bolivia, Plurinational State of"],
  TW: ["Taiwan"], HK: ["Hong Kong SAR"], MO: ["Macau"], CZ: ["Czech Republic", "Czechia"], MK: ["Macedonia", "Macedonia, the Former Yugoslav Republic of"],
  PS: ["Palestine, State of", "Palestinian Territory"], CD: ["Congo, The Democratic Republic of the", "DR Congo"],
  CG: ["Congo"], CI: ["Cote d'Ivoire", "Ivory Coast"], TR: ["Turkey", "Turkiye"], NL: ["Netherlands", "The Netherlands"],
  XK: ["Kosovo"], VA: ["Holy See (Vatican City State)"], FM: ["Micronesia, Federated States of"],
  BN: ["Brunei Darussalam"], SZ: ["Swaziland", "Eswatini"], CV: ["Cape Verde"], MM: ["Burma"],
};

const en = iso.getNames("en", { select: "all" });
const ja = iso.getNames("ja", { select: "official" });
const out = {};
for (const [c, ll] of Object.entries(centroids)) {
  const names = [...(en[c] || []), ...(EXTRA_ALIASES[c] || [])];
  if (!names.length) continue;
  out[c] = { en: (en[c] || names)[0], ja: ja[c] || null, lat: ll[0], lon: ll[1],
             aliases: [...new Set(names)] };
}
out.XK.ja = out.XK.ja || "コソボ";

const map = {
  source: "Natural Earth 1:110m via world-atlas@2.0.2; generated by tools/build-world-map.js",
  width: W, viewBox: [0, Math.floor(ymin), W, Math.ceil(ymax - ymin)],
  projection: { name: "naturalEarth1", scale: k, translate: [tx, ty] },
  countries: shapes,
};
fs.writeFileSync(path.join(ROOT, "frontend/world-110m.json"), JSON.stringify(map));
fs.writeFileSync(path.join(ROOT, "backend/soc_geo_countries.json"),
  JSON.stringify({ source: "Natural Earth centroids + i18n-iso-countries names; tools/build-world-map.js", countries: out }, null, 0));

// Self-check: the frontend formula must match d3 exactly.
function ne1(lon, lat) {
  const l = lon * Math.PI / 180, p = lat * Math.PI / 180, p2 = p * p, p4 = p2 * p2;
  const x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)));
  const y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
  return [tx + k * x, ty - k * y];
}
for (const pt of [[139.7, 35.7], [-98, 39], [2.3, 48.8], [151, -33]]) {
  const a = projection(pt), b = ne1(...pt);
  if (Math.abs(a[0] - b[0]) > 0.01 || Math.abs(a[1] - b[1]) > 0.01) throw new Error("projection mismatch " + pt);
}
console.log(`countries drawn: ${shapes.length}, geo table: ${Object.keys(out).length}, viewBox: ${map.viewBox}`);
