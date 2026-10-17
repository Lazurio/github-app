// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";

const APACHE_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const GITHUB_CLI_LICENSE_SHA256 = "6da4adc42392c8485e40b4251c7e332fc3352df1947c9ffade71dd60b14a7a4f";
const JOSE_VERSION = "6.2.12";
const JOSE_LICENSE_SHA256 = "8078b0829d6c3e9ecde2f003e1966e4cad3efc6e7a640efbab0313cc166b1af1";

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const packageMetadata = JSON.parse(read("package.json"));
assert.equal(packageMetadata.private, true, "npm publishing must remain disabled");
assert.equal(packageMetadata.license, "Apache-2.0", "package license must use an SPDX identifier");
assert.equal(
  packageMetadata.repository?.url,
  "git+https://github.com/Lazurio/github-app.git",
  "package repository metadata must identify the public source",
);

// jose is the only runtime dependency, pinned exactly; the Worker bundle carries it.
assert.deepEqual(
  packageMetadata.dependencies,
  { jose: JOSE_VERSION },
  "jose must remain the only runtime dependency, pinned to the version the notices name",
);

assert.equal(sha256("LICENSE"), APACHE_LICENSE_SHA256, "Apache-2.0 license text drifted");
assert.equal(
  sha256("third_party/github-cli/LICENSE"),
  GITHUB_CLI_LICENSE_SHA256,
  "the pinned GitHub CLI 2.97.0 MIT license text drifted",
);
assert.equal(
  sha256("third_party/jose/LICENSE.md"),
  JOSE_LICENSE_SHA256,
  `the pinned jose ${JOSE_VERSION} MIT license text drifted`,
);

const notice = read("THIRD_PARTY_NOTICES.md");
assert.match(notice, /GitHub CLI 2\.97\.0 is licensed under the MIT License/);
assert.match(notice, new RegExp(`jose ${JOSE_VERSION.replaceAll(".", "\\.")} is licensed under the MIT\\s+License`));
assert.match(notice, /not affiliated with,\s+sponsored by,\s+or endorsed by GitHub, Inc\./);

const readme = read("README.md");
assert.match(readme, /Apache License 2\.0/);
assert.match(readme, /not affiliated with,\s+sponsored by,\s+or endorsed by GitHub, Inc\./);

const dockerfile = read("Dockerfile");
assert.match(dockerfile, /^# SPDX-License-Identifier: Apache-2\.0$/m);
assert.match(dockerfile, /org\.opencontainers\.image\.licenses="Apache-2\.0"/);
assert.match(dockerfile, /third_party\/github-cli\/LICENSE/);

const releaseWorkflow = read(".github/workflows/release.yml");
assert.match(releaseWorkflow, /org\.opencontainers\.image\.licenses=Apache-2\.0/);
assert.match(releaseWorkflow, /third-party\/github-cli\/LICENSE/);

for (const file of [
  "src/core.mjs",
  "src/broker.mjs",
  "src/worker.mjs",
  "src/oidc.mjs",
  "adapter/broker-client.mjs",
  "adapter/brokered-gh.mjs",
  "scripts/check-licenses.mjs",
  "test/broker.test.mjs",
  "test/brokered-gh.test.mjs",
  "test/worker.test.mjs",
  "test/oidc.test.mjs",
  ".github/workflows/ci.yml",
  ".github/workflows/release.yml",
]) {
  assert.match(
    read(file).split("\n").slice(0, 2).join("\n"),
    /SPDX-License-Identifier: Apache-2\.0/,
    `${file} lacks its SPDX header`,
  );
}

process.stdout.write("License check: PASS\n");
