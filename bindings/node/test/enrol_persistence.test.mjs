import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

const tmpDir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

function closedPortEndpoint() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(`direct:127.0.0.1:${port}`));
    });
  });
}

test("a failed enrol with nothing new leaves roster.json alone", async () => {
  const hostDir = tmpDir("tendril-node-enr-host-");
  const cliDir = tmpDir("tendril-node-enr-cli-");
  const host = new Endpoint(hostDir, "enr-host");
  const cli = new Endpoint(cliDir, "enr-cli");
  try {
    const hostInfo = JSON.parse(host.infoJson());
    const cliInfo = JSON.parse(cli.infoJson());
    const token = host.mintEnrollmentToken(hostInfo.host_id, cliInfo.device_id, 900);
    const roster = path.join(cliDir, "roster.json");
    const enrol = async () =>
      assert.rejects(
        cli.enrollInitiate(
          await closedPortEndpoint(),
          hostInfo.host_id,
          Buffer.from(hostInfo.static_pub, "base64url"),
          Buffer.from(hostInfo.signing_pub, "base64url"),
          token,
        ),
      );

    await enrol();
    assert.equal(fs.existsSync(roster), false, "an enrol with nothing to persist");

    fs.writeFileSync(roster, '{"entries":{},"crls":{}}', { mode: 0o600 });
    const before = fs.statSync(roster, { bigint: true }).mtimeNs;
    await new Promise((r) => setTimeout(r, 20));
    await enrol();
    assert.equal(fs.statSync(roster, { bigint: true }).mtimeNs, before);
  } finally {
    host.close();
    cli.close();
  }
});
