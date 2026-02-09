import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";

export interface VerifyRequest {
  bundle: string;
  keys: string;
  keysDigest?: string;
  requireCosign?: boolean;
  ociRef?: string;
  allowExperimental?: boolean;
}

export interface ExecuteRequest {
  bundle: string;
  keys: string;
  keysDigest?: string;
  policy: string;
  input: string;
  receipt: string;
  requireCosign?: boolean;
  ociRef?: string;
  allowExperimental?: boolean;
}

export interface VerifyOutput {
  stdout: string;
}

export interface ExecuteOutput {
  stdout: string;
  receiptPath: string;
}

export interface Receipt {
  raw: unknown;
}

export type ErrorCode =
  | "INVALID_REQUEST"
  | "COMMAND_FAILED"
  | "IO_ERROR"
  | "JSON_ERROR";

export class SdkError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "SdkError";
    this.code = code;
  }
}

export interface CommandRunner {
  run(args: string[]): Promise<string>;
}

export class CliRunner implements CommandRunner {
  readonly bin: string;

  constructor(bin = "provenact-cli") {
    this.bin = bin;
  }

  run(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];

      child.stdout.on("data", (chunk) => stdoutChunks.push(Buffer.from(chunk)));
      child.stderr.on("data", (chunk) => stderrChunks.push(Buffer.from(chunk)));
      child.on("error", (err) => reject(new SdkError("IO_ERROR", err.message)));
      child.on("close", (code) => {
        if (code === 0) {
          resolve(Buffer.concat(stdoutChunks).toString("utf8"));
          return;
        }
        reject(
          new SdkError(
            "COMMAND_FAILED",
            Buffer.concat(stderrChunks).toString("utf8").trim() ||
              `${this.bin} exited with status ${code}`
          )
        );
      });
    });
  }
}

export class ProvenactSdk {
  private readonly runner: CommandRunner;

  constructor(runner: CommandRunner = new CliRunner()) {
    this.runner = runner;
  }

  async verifyBundle(req: VerifyRequest): Promise<VerifyOutput> {
    validateVerifyRequest(req);

    const keysDigest = req.keysDigest ?? (await digestFile(req.keys));
    const args = ["verify", "--bundle", req.bundle, "--keys", req.keys];
    args.push("--keys-digest", keysDigest);
    if (req.requireCosign) {
      args.push("--require-cosign");
    }
    if (req.ociRef) {
      args.push("--oci-ref", req.ociRef);
    }
    if (req.allowExperimental) {
      args.push("--allow-experimental");
    }

    const stdout = await this.runner.run(args);
    return { stdout };
  }

  async executeVerified(req: ExecuteRequest): Promise<ExecuteOutput> {
    validateExecuteRequest(req);

    const keysDigest = req.keysDigest ?? (await digestFile(req.keys));
    const args = [
      "run",
      "--bundle",
      req.bundle,
      "--keys",
      req.keys,
      "--keys-digest",
      keysDigest,
      "--policy",
      req.policy,
      "--input",
      req.input,
      "--receipt",
      req.receipt,
    ];
    if (req.requireCosign) {
      args.push("--require-cosign");
    }
    if (req.ociRef) {
      args.push("--oci-ref", req.ociRef);
    }
    if (req.allowExperimental) {
      args.push("--allow-experimental");
    }

    const stdout = await this.runner.run(args);
    return { stdout, receiptPath: req.receipt };
  }

  async parseReceipt(path: string): Promise<Receipt> {
    let data: string;
    try {
      data = await readFile(path, "utf8");
    } catch (err) {
      throw new SdkError("IO_ERROR", (err as Error).message);
    }

    try {
      return { raw: JSON.parse(data) };
    } catch (err) {
      throw new SdkError("JSON_ERROR", (err as Error).message);
    }
  }
}

async function digestFile(path: string): Promise<string> {
  try {
    const data = await readFile(path);
    return `sha256:${createHash("sha256").update(data).digest("hex")}`;
  } catch (err) {
    throw new SdkError("IO_ERROR", (err as Error).message);
  }
}

export const experimental = {
  async validateManifestV1(runner: CommandRunner, manifest: string): Promise<string> {
    return runner.run(["experimental-validate-manifest-v1", "--manifest", manifest]);
  },

  async validateReceiptV1(runner: CommandRunner, receipt: string): Promise<string> {
    return runner.run(["experimental-validate-receipt-v1", "--receipt", receipt]);
  },
};

function validateVerifyRequest(req: VerifyRequest): void {
  if (req.requireCosign && !req.ociRef) {
    throw new SdkError("INVALID_REQUEST", "ociRef is required when requireCosign is true");
  }
}

function validateExecuteRequest(req: ExecuteRequest): void {
  if (req.requireCosign && !req.ociRef) {
    throw new SdkError("INVALID_REQUEST", "ociRef is required when requireCosign is true");
  }
}
