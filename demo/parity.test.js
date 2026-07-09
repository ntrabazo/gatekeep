/*
 * Cross-language parity test: the JS port must reproduce the Python engine
 * exactly on the full harness corpus.
 *
 *   node demo/parity.test.js          (exit 0 = parity holds)
 *
 * Checks, per corpus entry:
 *   1. decided action  == Python action == harness expectation
 *   2. redacted text   == Python redacted text
 *   3. findings        == Python findings (category, detector, span, preview)
 *   4. categories/detectors CSVs == Python audit CSVs
 *   5. JS sha256       == Python hashlib sha256 == node:crypto sha256
 * Plus: demo/corpus.js is in sync with harness/corpus.jsonl.
 *
 * expected.json comes from the real Python engine: demo/dump_expected.py.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const Gatekeep = require("./gatekeep.js");
const CORPUS_JS = require("./corpus.js");

const root = path.resolve(__dirname, "..");
const corpus = fs
  .readFileSync(path.join(root, "harness", "corpus.jsonl"), "utf-8")
  .split(/\r?\n/)
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l));
const expected = JSON.parse(fs.readFileSync(path.join(__dirname, "expected.json"), "utf-8"));

const failures = [];
function check(i, name, got, want) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) failures.push(`  #${String(i).padStart(2, "0")} ${name}: got ${g}, want ${w}`);
}

// corpus.js in sync with corpus.jsonl
if (JSON.stringify(CORPUS_JS) !== JSON.stringify(corpus)) {
  failures.push("  demo/corpus.js is out of sync with harness/corpus.jsonl — run node demo/build_corpus.js");
}
if (expected.length !== corpus.length) {
  failures.push(`  expected.json has ${expected.length} entries, corpus has ${corpus.length} — rerun demo/dump_expected.py`);
}

const stats = { secret: { total: 0, hit: 0 }, pii: { total: 0, hit: 0 }, clean: { total: 0, hit: 0 } };

corpus.forEach((e, idx) => {
  const i = idx + 1;
  const exp = expected[idx];
  const findings = Gatekeep.runAll(e.text, Gatekeep.POLICIES);
  const decision = Gatekeep.decide([e.text], [findings], Gatekeep.POLICIES);

  stats[e.label].total += 1;
  if (decision.action === e.expect) stats[e.label].hit += 1;

  check(i, "action vs harness expect", decision.action, e.expect);
  if (!exp) return;
  check(i, "action vs python", decision.action, exp.action);
  check(i, "redacted text", decision.redactedTexts[0], exp.redacted);
  check(i, "findings", findings, exp.findings);
  check(i, "categories csv", [...new Set(findings.map((f) => f.category))].sort().join(","), exp.categories);
  check(i, "detectors csv", [...new Set(findings.map((f) => f.detector))].sort().join(","), exp.detectors);

  const jsHash = Gatekeep.sha256Hex(e.text);
  const nodeHash = crypto.createHash("sha256").update(e.text, "utf-8").digest("hex");
  check(i, "sha256 vs python", jsHash, exp.sha256);
  check(i, "sha256 vs node:crypto", jsHash, nodeHash);
});

console.log("GATEKEEP JS-PORT PARITY (offline)");
console.log(`${"category".padEnd(10)} ${"total".padStart(5)} ${"hit".padStart(5)} ${"miss".padStart(5)}`);
for (const label of ["secret", "pii", "clean"]) {
  const s = stats[label];
  console.log(`${label.padEnd(10)} ${String(s.total).padStart(5)} ${String(s.hit).padStart(5)} ${String(s.total - s.hit).padStart(5)}`);
}

const dirtyTotal = stats.secret.total + stats.pii.total;
const dirtyHit = stats.secret.hit + stats.pii.hit;
console.log(`\nCATCH RATE ${dirtyHit}/${dirtyTotal} (${((dirtyHit / dirtyTotal) * 100).toFixed(1)}%)`);

if (failures.length) {
  console.log(`\nparity failures (${failures.length}):`);
  console.log(failures.slice(0, 40).join("\n"));
}
const ok = failures.length === 0 && dirtyHit === dirtyTotal && stats.clean.hit === stats.clean.total;
console.log(`RESULT: ${ok ? "PASS — JS port matches the Python engine on all " + corpus.length + " corpus entries" : "FAIL"}`);
process.exit(ok ? 0 : 1);
