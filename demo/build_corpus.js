/*
 * Regenerate demo/corpus.js from harness/corpus.jsonl and
 * demo/injection_corpus.js from harness/injection_corpus.jsonl
 * (the source of truth). Run after any corpus change:  node demo/build_corpus.js
 */
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");

function build(sourceName, outName, globalName) {
  const lines = fs
    .readFileSync(path.join(root, "harness", sourceName), "utf-8")
    .split(/\r?\n/)
    .filter((l) => l.trim());
  const entries = lines.map((l) => JSON.parse(l));

  const body = entries.map((e) => "  " + JSON.stringify(e)).join(",\n");
  const out = `/*
 * GENERATED from harness/${sourceName} — do not edit by hand.
 * Regenerate with:  node demo/build_corpus.js
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.${globalName} = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  return [
${body}
  ];
});
`;

  fs.writeFileSync(path.join(__dirname, outName), out, "utf-8");
  console.log(`wrote ${entries.length} corpus entries to demo/${outName}`);
}

build("corpus.jsonl", "corpus.js", "GatekeepCorpus");
build("injection_corpus.jsonl", "injection_corpus.js", "GatekeepInjectionCorpus");
