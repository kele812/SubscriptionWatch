import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
const revision = "f2aca7940600207cc75ab4fe0c91003b6bd6dfeb";
const response = await fetch(
  `https://codeload.github.com/xboardnext999/XboardNode-Plus/tar.gz/${revision}`,
  { signal: AbortSignal.timeout(120000) },
);
if (!response.ok) throw Error(`upstream download HTTP ${response.status}`);
const data = Buffer.from(await response.arrayBuffer());
// Digest pinned together with reviewed upstream source, not a moving branch.
const expected =
  "cf1eb61b996f21a5c0fa832673e0448b7e91d788fe97fa98b15b5c183e46746c";
if (createHash("sha256").update(data).digest("hex") !== expected)
  throw Error("upstream checksum mismatch");
writeFileSync("upstream.tar.gz", data);
