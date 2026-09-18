// Offline only: stop the watch service before running this command.
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  statfs,
} from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as tar from "tar";
import { digest } from "./backup.mjs";
export async function restoreBackup(archive, target, options = {}) {
  target = path.resolve(target);
  archive = path.resolve(archive);
  if (archive.startsWith(target + path.sep) && !options.internalArchive)
    throw Error("备份压缩包必须位于目标数据目录之外");
  await mkdir(target, { recursive: true });
  const stage = await mkdtemp(path.join(target, ".restore-"));
  let previous;
  try {
    const names = new Set();
    let total = 0,
      invalid = false;
    const allowed = (n) =>
      [
        "watch.sqlite",
        "master.key",
        "manifest.json",
        "geo/current.json",
      ].includes(n) ||
      /^geo\/db-[a-f0-9]{48}\/GeoLite2-(City|ASN)\.mmdb$/.test(n);
    await tar.t({
      file: archive,
      strict: true,
      onReadEntry: (e) => {
        if (
          e.type !== "File" ||
          !allowed(e.path) ||
          names.has(e.path) ||
          names.size >= 7
        )
          invalid = true;
        if (
          (e.path === "manifest.json" && e.size > 65536) ||
          (e.path === "master.key" && e.size !== 32)
        )
          invalid = true;
        names.add(e.path);
        total += e.size;
      },
    });
    if (
      invalid ||
      !names.has("manifest.json") ||
      !names.has("watch.sqlite") ||
      !names.has("master.key")
    )
      throw Error("备份校验失败：包含不允许的路径、重复项、错误尺寸或缺少必要文件");
    if (!Number.isSafeInteger(total) || total > 80 * 1024 ** 3)
      throw Error("备份尺寸超出限制");
    const space = await statfs(target);
    if (total + 64 * 1024 ** 2 > Number(space.bavail) * Number(space.bsize))
      throw Error("剩余空间不足以解压备份，请先释放空间");
    await tar.x({ file: archive, cwd: stage, strict: true, noChmod: true });
    const manifest = JSON.parse(
      await readFile(path.join(stage, "manifest.json"), "utf8"),
    );
    if (
      manifest.format !== "subscriptionwatch-backup" ||
      manifest.version !== 1 ||
      !manifest.files ||
      Object.keys(manifest.files).length !== names.size - 1
    )
      throw Error("备份清单无效");
    for (const name of names) {
      if (name === "manifest.json") continue;
      const info = manifest.files[name];
      if (
        !info ||
        (await stat(path.join(stage, name))).size !== info.size ||
        (await digest(path.join(stage, name))) !== info.sha256
      )
        throw Error("备份文件校验失败：" + name);
    }
    if ((await readFile(path.join(stage, "master.key"))).length !== 32)
      throw Error("加密密钥无效");
    const db = new DatabaseSync(path.join(stage, "watch.sqlite"));
    try {
      if (
        Object.values(db.prepare("PRAGMA quick_check").get())[0] !== "ok" ||
        !db
          .prepare("SELECT name FROM sqlite_master WHERE name='accounts'")
          .get()
      )
        throw Error("数据库校验失败");
      // A restored snapshot must not re-enable old commands or send stale messages.
      db.exec(
        "UPDATE ban_settings SET enabled=0; UPDATE ban_actions SET status='已取消',message='备份恢复已停用旧任务，请人工核对' WHERE status IN ('待领取','已下发','处理中'); UPDATE ban_tasks SET result='expired' WHERE result IS NULL; DELETE FROM control_clients; DELETE FROM control_nonces; DELETE FROM risk_observation; DELETE FROM outbox; DELETE FROM tg_confirm; PRAGMA wal_checkpoint(TRUNCATE);",
      );
    } finally {
      db.close();
    }
    if (names.has("geo/current.json")) {
      const current = JSON.parse(
        await readFile(path.join(stage, "geo/current.json"), "utf8"),
      );
      if (
        !/^db-[a-f0-9]{48}$/.test(current.directory) ||
        !names.has(`geo/${current.directory}/GeoLite2-City.mmdb`) ||
        !names.has(`geo/${current.directory}/GeoLite2-ASN.mmdb`)
      )
        throw Error("IP数据库清单不完整");
    }
    await options.beforeReplace?.();
    previous = path.join(target, "restore-previous-" + Date.now());
    await mkdir(previous);
    const existing = (await readdir(target)).filter(
      (n) =>
        n !== path.basename(stage) &&
        n !== path.basename(previous) &&
        !(options.keep || []).includes(n) &&
        !n.startsWith("restore-previous-"),
    );
    const moved = [],
      installed = [];
    try {
      for (const n of existing) {
        await rename(path.join(target, n), path.join(previous, n));
        moved.push(n);
      }
      for (const n of [
        "watch.sqlite",
        "master.key",
        ...(names.has("geo/current.json") ? ["geo"] : []),
      ]) {
        await rename(path.join(stage, n), path.join(target, n));
        installed.push(n);
      }
      await options.afterReplace?.();
    } catch (e) {
      for (const n of installed)
        await rename(path.join(target, n), path.join(stage, n));
      // Opening the replacement can create geo/, WAL or SHM files. Preserve
      // those separately before restoring original files of the same name.
      const leftovers = (await readdir(target)).filter(
        (n) =>
          n !== path.basename(stage) &&
          n !== path.basename(previous) &&
          !n.startsWith("restore-previous-") &&
          !(options.keep || []).includes(n) &&
          (moved.includes(n) || !existing.includes(n)),
      );
      if (leftovers.length) {
        const rejected = path.join(stage, "rejected-runtime");
        await mkdir(rejected);
        for (const n of leftovers)
          await rename(path.join(target, n), path.join(rejected, n));
      }
      for (const n of moved)
        await rename(path.join(previous, n), path.join(target, n));
      await options.afterRollback?.();
      throw e;
    }
    return previous;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  if (process.argv.length !== 5 || process.argv[4] !== "--service-stopped") {
    console.error(
      "先停止风控服务，再执行：node restore.mjs /backup/file.tar.gz /data --service-stopped",
    );
    process.exitCode = 1;
  } else
    try {
      console.log(
        "恢复完成；原数据保留在：" +
          (await restoreBackup(process.argv[2], process.argv[3])),
      );
    } catch (e) {
      console.error(e.message);
      process.exitCode = 1;
    }
}
