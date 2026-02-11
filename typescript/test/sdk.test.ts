import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

import {
  CliRunner,
  ProvenactSdk,
  SdkError,
  type CommandRunner,
  type ExecuteRequest,
  type VerifyRequest,
} from "../src/index";

class FakeRunner implements CommandRunner {
  lastArgs: string[] = [];

  async run(args: string[]): Promise<string> {
    this.lastArgs = args;
    return "OK";
  }
}

test("verifyBundle builds expected args", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: VerifyRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    requireCosign: true,
    ociRef: "ghcr.io/acme/skill:1",
    cosignKey: "./cosign.pub",
    cosignCertIdentity: "https://github.com/acme/workflow@refs/heads/main",
    cosignCertOidcIssuer: "https://token.actions.githubusercontent.com",
    allowExperimental: true,
  };

  await sdk.verifyBundle(req);

  assert.deepEqual(runner.lastArgs.slice(0, 5), [
    "verify",
    "--bundle",
    "./bundle",
    "--keys",
    "./keys.json",
  ]);
  assert.ok(runner.lastArgs.includes("--keys-digest"));
  assert.ok(runner.lastArgs.includes("sha256:abc"));
  assert.ok(runner.lastArgs.includes("--require-cosign"));
  assert.ok(runner.lastArgs.includes("--oci-ref"));
  assert.ok(runner.lastArgs.includes("ghcr.io/acme/skill:1"));
  assert.ok(runner.lastArgs.includes("--cosign-key"));
  assert.ok(runner.lastArgs.includes("./cosign.pub"));
  assert.ok(runner.lastArgs.includes("--cosign-cert-identity"));
  assert.ok(runner.lastArgs.includes("https://github.com/acme/workflow@refs/heads/main"));
  assert.ok(runner.lastArgs.includes("--cosign-cert-oidc-issuer"));
  assert.ok(runner.lastArgs.includes("https://token.actions.githubusercontent.com"));
  assert.ok(runner.lastArgs.includes("--allow-experimental"));
});

test("verifyBundle trims keysDigest before forwarding", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  await sdk.verifyBundle({
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "  sha256:abc  ",
  });

  const digestFlagIndex = runner.lastArgs.indexOf("--keys-digest");
  assert.notEqual(digestFlagIndex, -1);
  assert.equal(runner.lastArgs[digestFlagIndex + 1], "sha256:abc");
});

test("executeVerified enforces ociRef when requireCosign is true", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: ExecuteRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    policy: "./policy.json",
    input: "./input.json",
    receipt: "./receipt.json",
    requireCosign: true,
  };

  await assert.rejects(() => sdk.executeVerified(req), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("executeVerified enforces cosignKey when requireCosign is true", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: ExecuteRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    policy: "./policy.json",
    input: "./input.json",
    receipt: "./receipt.json",
    requireCosign: true,
    ociRef: "ghcr.io/acme/skill:1",
  };

  await assert.rejects(() => sdk.executeVerified(req), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("executeVerified enforces cosignCertIdentity when requireCosign is true", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: ExecuteRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    policy: "./policy.json",
    input: "./input.json",
    receipt: "./receipt.json",
    requireCosign: true,
    ociRef: "ghcr.io/acme/skill:1",
    cosignKey: "./cosign.pub",
  };

  await assert.rejects(() => sdk.executeVerified(req), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("executeVerified enforces cosignCertOidcIssuer when requireCosign is true", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: ExecuteRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    policy: "./policy.json",
    input: "./input.json",
    receipt: "./receipt.json",
    requireCosign: true,
    ociRef: "ghcr.io/acme/skill:1",
    cosignKey: "./cosign.pub",
    cosignCertIdentity: "https://github.com/acme/workflow@refs/heads/main",
  };

  await assert.rejects(() => sdk.executeVerified(req), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("parseReceipt reads json", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);
  const dir = await mkdtemp(join(tmpdir(), "provenact-sdk-ts-"));
  const receiptPath = join(dir, "receipt.json");
  await writeFile(receiptPath, '{"schema_version":"1.0.0"}', "utf8");

  const receipt = await sdk.parseReceipt(receiptPath);
  assert.deepEqual(receipt.raw, { schema_version: "1.0.0" });
});

test("verifyBundle rejects missing keysDigest", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  await assert.rejects(() => sdk.verifyBundle({
    bundle: "./bundle",
    keys: "./keys.json",
  } as unknown as VerifyRequest), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("executeVerified rejects blank ociRef when requireCosign is true", async () => {
  const runner = new FakeRunner();
  const sdk = new ProvenactSdk(runner);

  const req: ExecuteRequest = {
    bundle: "./bundle",
    keys: "./keys.json",
    keysDigest: "sha256:abc",
    policy: "./policy.json",
    input: "./input.json",
    receipt: "./receipt.json",
    requireCosign: true,
    ociRef: " ",
    cosignKey: "./cosign.pub",
    cosignCertIdentity: "https://github.com/acme/workflow@refs/heads/main",
    cosignCertOidcIssuer: "https://token.actions.githubusercontent.com",
  };

  await assert.rejects(() => sdk.executeVerified(req), (err: unknown) => {
    assert.ok(err instanceof SdkError);
    assert.equal((err as SdkError).code, "INVALID_REQUEST");
    return true;
  });
});

test("smoke verify against local provenact vector when configured", async (t: TestContext) => {
  const root = process.env.PROVENACT_VECTOR_ROOT;
  if (!root) {
    t.skip("set PROVENACT_VECTOR_ROOT to run smoke verify test");
    return;
  }

  const cli = process.env.PROVENACT_CLI_BIN ?? "provenact-cli";
  const sdk = new ProvenactSdk(new CliRunner(cli));
  const keysPath = join(root, "test-vectors/good/minimal-zero-cap/public-keys.json");
  const keysDigest = await sha256File(keysPath);

  const out = await sdk.verifyBundle({
    bundle: join(root, "test-vectors/good/minimal-zero-cap"),
    keys: keysPath,
    keysDigest,
  });

  assert.match(out.stdout, /^OK (verify )?artifact=sha256:[a-f0-9]{64} signers=\d+$/m);
});

async function sha256File(path: string): Promise<string> {
  const data = await readFile(path);
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}
