// Builds public/regions.json: Russia's federal subjects as ready SVG paths, so the site needs no map library,
// no tiles and no third-party requests.
//
// Source: Natural Earth 10m admin-1 (public domain), ne_10m_admin_1_states_provinces.geojson:
//   node tools/build-regions.mjs <path to that file>
// Codes are ISO 3166-2 without the "RU-" prefix: the same as Cloudflare's request.cf.regionCode.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import mapshaper from "mapshaper";
import { geoIdentity, geoPath } from "d3-geo";

const source = process.argv[2];
if (!source) {
  console.error("usage: node tools/build-regions.mjs <ne_10m_admin_1_states_provinces.geojson>");
  process.exit(2);
}

// Natural Earth slips: MOW/MOS swapped, ALT named like AL, one unnamed sliver (RU-X01~) beside Yamal.
const FIX_NAME = {
  MOW: "Москва",
  MOS: "Московская область",
  ALT: "Алтайский край",
  AL: "Республика Алтай",
  SE: "Северная Осетия",
  KHM: "Ханты-Мансийский АО",
  YAN: "Ямало-Ненецкий АО",
  NEN: "Ненецкий АО",
  CHU: "Чукотский АО",
  YEV: "Еврейская АО",
};
// The Moscow city and Moscow oblast shapes carry each other's ISO code (RU-MOW is the oblast's ring): swap them,
// so Cloudflare's regionCode MOW (the city) lands on the city.
const FIX_CODE = { "X01~": "YAN", MOW: "MOS", MOS: "MOW" };

const world = JSON.parse(readFileSync(source, "utf8"));
const features = world.features
  .filter((f) => f.properties.adm0_a3 === "RUS")
  .map((f) => {
    const iso = String(f.properties.iso_3166_2);
    const raw = iso.replace(/^(RU|UA)-/, "");
    const code = FIX_CODE[raw] ?? raw;
    return {
      type: "Feature",
      properties: { code, name: FIX_NAME[code] ?? f.properties.name_ru ?? f.properties.name ?? code },
      geometry: f.geometry,
    };
  });

// Albers equal-area for Russia: no Mercator blow-up of the north. Simplify, merge pieces of one code.
const output = await mapshaper.applyCommands(
  [
    "-i in.json",
    "-proj +proj=aea +lat_1=52 +lat_2=64 +lon_0=100 +datum=WGS84",
    "-simplify 3% weighting=0.7 keep-shapes",
    "-filter-slivers min-area=200km2",
    "-dissolve2 code copy-fields=name",
    "-o out.json format=geojson",
  ].join(" "),
  { "in.json": { type: "FeatureCollection", features } },
);
const projected = JSON.parse(output["out.json"]);

const WIDTH = 1000;
const fit = geoIdentity().reflectY(true).fitWidth(WIDTH, projected);
const path = geoPath(fit).digits(1);
const [[, y0], [, y1]] = path.bounds(projected);
const height = Math.ceil(y1 - y0);
fit.translate([fit.translate()[0], fit.translate()[1] - y0]);

const regions = projected.features
  .map((f) => {
    const [cx, cy] = path.centroid(f);
    return { code: f.properties.code, name: f.properties.name, d: path(f), cx: Math.round(cx), cy: Math.round(cy) };
  })
  .sort((a, b) => a.name.localeCompare(b.name, "ru"));

const out = fileURLToPath(new URL("../public/regions.json", import.meta.url));
const json = JSON.stringify({
  source: "Natural Earth 10m admin-1 (public domain), simplified",
  width: WIDTH,
  height,
  regions,
});
writeFileSync(out, json);
console.log(`${regions.length} regions, ${WIDTH}x${height}, ${(json.length / 1024).toFixed(0)} KB → ${out}`);
