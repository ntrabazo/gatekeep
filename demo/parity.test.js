/*
 * Cross-language parity test: the JS port must reproduce the Python engine
 * exactly on the full harness corpus AND the injection corpus.
 *
 *   node demo/parity.test.js          (exit 0 = parity holds)
 *
 * Checks, per harness-corpus entry:
 *   1. decided action  == Python action == harness expectation
 *   2. redacted text   == Python redacted text
 *   3. findings        == Python findings (category, detector, span, preview)
 *   4. categories/detectors CSVs == Python audit CSVs
 *   5. JS sha256       == Python hashlib sha256 == node:crypto sha256
 * Checks, per injection-corpus entry:
 *   6. findings (incl. per-finding score) == Python findings
 *   7. document score == Python document_score
 *   8. decide() action + matched rules in shadow AND enforce mode == Python
 *   9. flagged at block_threshold == corpus expect_flag
 * Plus: demo/corpus.js + demo/injection_corpus.js are in sync with harness/*.jsonl.
 *
 * expected*.json come from the real Python engine: demo/dump_expected.py.
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

/* ---------- injection corpus ---------- */
const INJECTION_CORPUS_JS = require("./injection_corpus.js");
const injectionCorpus = fs
  .readFileSync(path.join(root, "harness", "injection_corpus.jsonl"), "utf-8")
  .split(/\r?\n/)
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l));
const expectedInjection = JSON.parse(
  fs.readFileSync(path.join(__dirname, "expected_injection.json"), "utf-8")
);

if (JSON.stringify(INJECTION_CORPUS_JS) !== JSON.stringify(injectionCorpus)) {
  failures.push("  demo/injection_corpus.js is out of sync with harness/injection_corpus.jsonl — run node demo/build_corpus.js");
}
if (expectedInjection.length !== injectionCorpus.length) {
  failures.push(`  expected_injection.json has ${expectedInjection.length} entries, corpus has ${injectionCorpus.length} — rerun demo/dump_expected.py`);
}

const enforcePolicies = JSON.parse(JSON.stringify(Gatekeep.POLICIES));
enforcePolicies.injection.mode = "enforce";
const threshold = Gatekeep.POLICIES.injection.blockThreshold;

const injStats = { attacks: { total: 0, hit: 0 }, benign: { total: 0, hit: 0 } };

injectionCorpus.forEach((e, idx) => {
  const i = "inj#" + String(idx + 1).padStart(3, "0");
  const exp = expectedInjection[idx];
  const findings = Gatekeep.runAll(e.text, Gatekeep.POLICIES);
  const injOnly = findings.filter((f) => f.category === "injection");
  const docScore = Gatekeep.documentScore(injOnly);
  const shadowD = Gatekeep.decide([e.text], [findings], Gatekeep.POLICIES);
  const enforceD = Gatekeep.decide([e.text], [findings], enforcePolicies);

  const flagged = docScore >= threshold;
  const bucket = e.label === "injection" ? injStats.attacks : injStats.benign;
  bucket.total += 1;
  if (flagged === e.expect_flag) bucket.hit += 1;
  check(i, "flagged vs expect_flag", flagged, e.expect_flag);

  if (!exp) return;
  check(i, "findings", findings, exp.findings);
  if (Math.abs(docScore - exp.document_score) > 1e-6) {
    failures.push(`  ${i} document score: got ${docScore}, want ${exp.document_score}`);
  }
  if (Math.abs(shadowD.injectionScore - exp.injection_score) > 1e-6) {
    failures.push(`  ${i} injection score: got ${shadowD.injectionScore}, want ${exp.injection_score}`);
  }
  check(i, "injection categories", shadowD.injectionCategories, exp.injection_categories);
  check(i, "shadow action", shadowD.action, exp.action_shadow);
  check(i, "enforce action", enforceD.action, exp.action_enforce);
  check(i, "shadow matched rules", shadowD.matchedRules, exp.matched_shadow);
  check(i, "enforce matched rules", enforceD.matchedRules, exp.matched_enforce);
});

console.log(`\nINJECTION PARITY (block_threshold = ${threshold})`);
console.log(`attacks    ${String(injStats.attacks.total).padStart(5)} ${String(injStats.attacks.hit).padStart(5)} ${String(injStats.attacks.total - injStats.attacks.hit).padStart(5)}`);
console.log(`benign     ${String(injStats.benign.total).padStart(5)} ${String(injStats.benign.hit).padStart(5)} ${String(injStats.benign.total - injStats.benign.hit).padStart(5)}`);

if (failures.length) {
  console.log(`\nparity failures (${failures.length}):`);
  console.log(failures.slice(0, 40).join("\n"));
}
const injOk = injStats.attacks.hit === injStats.attacks.total && injStats.benign.hit === injStats.benign.total;
const ok = failures.length === 0 && dirtyHit === dirtyTotal && stats.clean.hit === stats.clean.total && injOk;
const totalEntries = corpus.length + injectionCorpus.length;
console.log(`RESULT: ${ok ? "PASS — JS port matches the Python engine on all " + totalEntries + " corpus entries" : "FAIL"}`);
process.exit(ok ? 0 : 1);
