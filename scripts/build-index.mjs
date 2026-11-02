#!/usr/bin/env node
// Sestaví docs/index.json ze všech SBOMů (SPDX + CycloneDX, JSON) v docs/SBOM-*-reports/.
// Bez závislostí, Node 18+. Spuštění: node scripts/build-index.mjs
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = join(ROOT, 'docs');
const SOURCES = [
  { dir: join(DOCS, 'SBOM-spdx-reports'), hint: 'SPDX' },
  { dir: join(DOCS, 'SBOM-cyclonedx-reports'), hint: 'CycloneDX' },
];

async function listJson(dir) {
  let out = [];
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out = out.concat(await listJson(p));
    else if (e.isFile() && e.name.toLowerCase().endsWith('.json')) out.push(p);
  }
  return out.sort();
}

const BAD_LICENSE = new Set(['', 'NOASSERTION', 'NONE']);

// pkg:type/namespace/name@version?qualifiers#subpath
function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  let s = purl.slice(4).split('#')[0].split('?')[0];
  let version = '';
  const at = s.lastIndexOf('@');
  if (at > s.indexOf('/')) { version = s.slice(at + 1); s = s.slice(0, at); }
  const parts = s.split('/').filter(Boolean);
  const type = (parts.shift() || '').toLowerCase();
  const dec = (x) => { try { return decodeURIComponent(x); } catch { return x; } };
  const name = dec(parts.pop() || '');
  const namespace = parts.map(dec).join('/');
  return { type, namespace, name, version: dec(version) };
}

function displayName(p) {
  if (!p.namespace) return p.name;
  if (p.type === 'maven') return `${p.namespace}:${p.name}`;
  return `${p.namespace}/${p.name}`;
}

function uniq(arr) { return [...new Set(arr.filter(Boolean))]; }

function component(name, version, purl, licenses, sbom) {
  const p = parsePurl(purl);
  let n = p ? displayName(p) : (name || '');
  if (!p && /^[a-z]+:/i.test(n) && !n.includes('/')) n = n.replace(/^[a-z]+:/i, ''); // "npm:express"
  if (!n) n = name || '(bez názvu)';
  return {
    name: n,
    version: version || (p && p.version) || '',
    purl: purl || '',
    ecosystem: p ? p.type : '',
    licenses: uniq(licenses),
    sbom,
  };
}

function parseSpdx(doc, id) {
  const pkgs = Array.isArray(doc.packages) ? doc.packages : [];
  const root = new Set(Array.isArray(doc.documentDescribes) ? doc.documentDescribes : []);
  for (const r of doc.relationships || []) {
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === doc.SPDXID) root.add(r.relatedSpdxElement);
    if (r.relationshipType === 'DESCRIBED_BY' && r.relatedSpdxElement === doc.SPDXID) root.add(r.spdxElementId);
  }
  const rootPkg = pkgs.find((p) => root.has(p.SPDXID));
  const comps = [];
  for (const p of pkgs) {
    if (root.has(p.SPDXID)) continue;
    const purl = (p.externalRefs || []).find((r) => (r.referenceType || '').toLowerCase() === 'purl')?.referenceLocator || '';
    const lic = [p.licenseConcluded, p.licenseDeclared].filter((l) => typeof l === 'string' && !BAD_LICENSE.has(l.trim()));
    comps.push(component(p.name, p.versionInfo, purl, lic.length ? [lic[0]] : [], id));
  }
  const name = (rootPkg && rootPkg.name) || doc.name || '';
  return { name, created: doc.creationInfo?.created || '', comps };
}

function cdxLicenses(list) {
  const out = [];
  for (const l of Array.isArray(list) ? list : []) {
    if (l.expression) out.push(l.expression);
    else if (l.license) out.push(l.license.id || l.license.name);
  }
  return out;
}

function parseCdx(doc, id) {
  const meta = doc.metadata?.component;
  const rootRef = meta?.['bom-ref'];
  const comps = [];
  const walk = (list) => {
    for (const c of Array.isArray(list) ? list : []) {
      const isRoot = rootRef ? c['bom-ref'] === rootRef : (meta && c.name === meta.name && c.version === meta.version);
      if (!isRoot) {
        const nm = c.group && !c.purl ? `${c.group}/${c.name}` : c.name;
        comps.push(component(nm, c.version, c.purl, cdxLicenses(c.licenses), id));
      }
      if (c.components) walk(c.components);
    }
  };
  walk(doc.components);
  const name = meta ? [meta.group, meta.name].filter(Boolean).join('/') + (meta.version ? `@${meta.version}` : '') : '';
  return { name, created: doc.metadata?.timestamp || '', comps };
}

function detect(raw) {
  if (raw && raw.sbom && typeof raw.sbom === 'object') raw = raw.sbom; // GitHub dependency-graph export
  if (raw?.spdxVersion || raw?.SPDXID) return ['SPDX', raw];
  if (raw?.bomFormat === 'CycloneDX' || (raw?.specVersion && raw?.components)) return ['CycloneDX', raw];
  return [null, raw];
}

async function main() {
  const sboms = [];
  let components = [];
  const seen = new Set();
  for (const src of SOURCES) {
    for (const file of await listJson(src.dir)) {
      const rel = relative(DOCS, file).split('\\').join('/');
      let raw;
      try { raw = JSON.parse(await readFile(file, 'utf8')); }
      catch (e) { console.warn(`! Přeskakuji ${rel}: neplatný JSON (${e.message})`); continue; }
      const [format, doc] = detect(raw);
      if (!format) { console.warn(`! Přeskakuji ${rel}: neznámý formát SBOM`); continue; }
      if (format !== src.hint) console.warn(`! ${rel}: formát ${format} je ve složce pro ${src.hint}`);
      let id = rel.replace(/^SBOM-([^/]+)-reports\//i, '$1/').replace(/\.json$/i, '');
      while (seen.has(id)) id += '_';
      seen.add(id);
      const r = format === 'SPDX' ? parseSpdx(doc, id) : parseCdx(doc, id);
      sboms.push({ id, file: rel, format, name: r.name || rel.split('/').pop().replace(/\.json$/i, ''), created: r.created, componentCount: r.comps.length });
      components = components.concat(r.comps);
      console.log(`✓ ${rel} (${format}): ${r.comps.length} komponent`);
    }
  }
  const out = { generatedAt: new Date().toISOString(), sboms, components };
  await writeFile(join(DOCS, 'index.json'), JSON.stringify(out, null, 1) + '\n');
  console.log(`Hotovo: ${sboms.length} SBOMů, ${components.length} komponent → docs/index.json`);
}

main().catch((e) => { console.error(e); process.exit(1); });
