import { backup } from "node:sqlite";
import {
  mkdtemp,
  copyFile,
  mkdir,
  rm,
  writeFile,
  stat,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import * as tar from "tar";
import { pipeline } from "node:stream/promises";
export async function digest(file) {
  const h = createHash("sha256");
  for await (const c of createReadStream(file)) h.update(c);
  return h.digest("hex");
}
export async function exportBackup(db, dataDir, geo, res) {
  const dir = await mkdtemp(path.join(dataDir, ".backup-"));
  try {
    await backup(db, path.join(dir, "watch.sqlite"));
    await copyFile(
      path.join(dataDir, "master.key"),
      path.join(dir, "master.key"),
    );
    const files = ["watch.sqlite", "master.key"];
    if (geo.current?.directory) {
      const d = geo.current.directory;
      if (!/^db-[a-f0-9]{48}$/.test(d)) throw Error("IP数据库目录无效");
      await mkdir(path.join(dir, "geo", d), { recursive: true });
      for (const file of [
        "current.json",
        `${d}/GeoLite2-City.mmdb`,
        `${d}/GeoLite2-ASN.mmdb`,
      ]) {
        await copyFile(
          path.join(dataDir, "geo", file),
          path.join(dir, "geo", file),
        );
        files.push("geo/" + file);
      }
    }
    const manifest = {
      format: "subscriptionwatch-backup",
      version: 1,
      created: new Date().toISOString(),
      files: {},
    };
    for (const file of files)
      manifest.files[file] = {
        size: (await stat(path.join(dir, file))).size,
        sha256: await digest(path.join(dir, file)),
      };
    await writeFile(
      path.join(dir, "manifest.json"),
      JSON.stringify(manifest, null, 2),
    );
    res.writeHead(200, {
      "Content-Type": "application/gzip",
      "Content-Disposition": `attachment; filename="subscriptionwatch-${Date.now()}.tar.gz"`,
      "Cache-Control": "private, no-store",
    });
    await pipeline(
      tar.c({ cwd: dir, gzip: true, portable: true }, [
        ...files,
        "manifest.json",
      ]),
      res,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
