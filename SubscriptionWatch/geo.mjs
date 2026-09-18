import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  renameSync,
  rmSync,
  readdirSync,
  statSync,
  createWriteStream,
  createReadStream,
} from "node:fs";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import * as maxmind from "maxmind";
import * as tar from "tar";
import { getConfig, setConfig, token } from "./model.mjs";
const editions = ["GeoLite2-City", "GeoLite2-ASN"];
export function parseGeoConfig(content) {
  if (typeof content !== "string" || Buffer.byteLength(content) > 32768)
    throw Error("配置文件须为32KB以内的文本文件");
  const fields = new Map();
  for (const raw of content.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^(AccountID|LicenseKey|EditionIDs)\s+(.+)$/);
    if (!match) continue;
    if (fields.has(match[1]))
      throw Error("配置文件中存在重复的 " + match[1] + " 字段");
    let value = match[2].replace(/\s+#.*$/, "").trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    )
      value = value.slice(1, -1);
    fields.set(match[1], value);
  }
  const account = fields.get("AccountID"),
    license = fields.get("LicenseKey");
  if (!account || !license) throw Error("文件缺少 AccountID 或 LicenseKey");
  if (/YOUR_|LICENSE_KEY_HERE|[<>]/i.test(license))
    throw Error("文件中的 LicenseKey 是占位符，请下载包含真实密钥的配置文件");
  const included = (fields.get("EditionIDs") || "")
    .split(/\s+/)
    .filter(Boolean);
  if (included.length && editions.some((name) => !included.includes(name)))
    throw Error(
      "配置文件需包含 GeoLite2-City 和 GeoLite2-ASN；本项目使用这两份数据库",
    );
  return { account, license, editions };
}
const allowedHosts = new Set([
  "download.maxmind.com",
  "mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com",
]);
export class GeoDatabase {
  constructor({ db, dataDir, encrypt, decrypt, fetcher = fetch }) {
    Object.assign(this, { db, encrypt, decrypt, fetcher });
    this.dir = path.join(dataDir, "geo");
    mkdirSync(this.dir, { recursive: true });
    this.cache = new Map();
    this.readers = {};
    this.busy = false;
    this.state = { phase: "未安装", progress: 0 };
    const manifest = path.join(this.dir, "current.json");
    if (existsSync(manifest)) {
      try {
        this.current = JSON.parse(readFileSync(manifest));
        for (const name of editions)
          this.readers[name] = new maxmind.Reader(
            readFileSync(
              path.join(this.dir, this.current.directory, name + ".mmdb"),
            ),
          );
        this.state.phase = "就绪";
      } catch {
        this.state.phase = "数据库加载失败，请重新安装";
        this.readers = {};
      }
    }
    for (const item of readdirSync(this.dir))
      if (
        /^(stage|db)-[a-f0-9]{48}$/.test(item) &&
        item !== this.current?.directory
      )
        rmSync(path.join(this.dir, item), { recursive: true, force: true });
  }
  status() {
    return {
      ...this.state,
      busy: this.busy,
      configured: !!getConfig(this.db, "maxmind"),
      current: this.current || null,
      check: getConfig(this.db, "geoCheck"),
    };
  }
  configure(account, license) {
    account =
      typeof account === "string" ? account.trim() : String(account ?? "");
    license = typeof license === "string" ? license.trim() : license;
    if (
      !/^\d{1,20}$/.test(account) ||
      typeof license !== "string" ||
      license.length < 10 ||
      license.length > 200
    )
      throw Error("请填写有效的 MaxMind Account ID 和 License Key");
    setConfig(
      this.db,
      "maxmind",
      this.encrypt(JSON.stringify({ account, license })),
    );
  }
  async request(edition, { method = "GET", suffix = "tar.gz" } = {}) {
    const stored = getConfig(this.db, "maxmind");
    if (!stored) throw Error("请先设置 MaxMind 下载凭据");
    const c = JSON.parse(this.decrypt(stored));
    let url = `https://download.maxmind.com/geoip/databases/${edition}/download?suffix=${suffix}`;
    for (let i = 0; i < 4; i++) {
      const target = new URL(url);
      if (target.protocol !== "https:" || !allowedHosts.has(target.hostname))
        throw Error("数据库下载重定向地址不受信任");
      const response = await this.fetcher(url, {
        method,
        redirect: "manual",
        signal: AbortSignal.timeout(120000),
        headers:
          target.hostname === "download.maxmind.com"
            ? {
                Authorization:
                  "Basic " +
                  Buffer.from(c.account + ":" + c.license).toString("base64"),
              }
            : {},
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel();
        url = new URL(response.headers.get("location"), url).href;
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel();
        const reason =
          response.status === 401
            ? "身份验证失败：请确认数字 Account ID 和完整 License Key 属于同一账号，密钥未被停用；不要填写邮箱、登录密码或密钥名称。"
            : response.status === 403
              ? "服务器拒绝访问：请检查账号是否具有该数据库下载权限，以及密钥限制。"
              : response.status === 429
                ? "下载请求过多，请稍后再试。"
                : "请检查账号下载权限和风控机网络。";
        const message = `MaxMind ${edition} 下载失败（HTTP ${response.status}）：${reason}`;
        throw Object.assign(Error(message), { publicMessage: message });
      }
      return response;
    }
    throw Error("下载重定向次数过多");
  }
  async check() {
    if (this.busy) throw Error("数据库任务正在进行");
    this.busy = true;
    try {
      const result = { checkedAt: Date.now(), databases: [] };
      for (const name of editions) {
        const r = await this.request(name, { method: "HEAD" });
        const modified = r.headers.get("last-modified");
        const local = this.current?.databases?.[name];
        result.databases.push({
          name,
          modified,
          available: !local
            ? true
            : !modified || !local.modified
              ? null
              : Date.parse(modified) > Date.parse(local.modified),
        });
      }
      setConfig(this.db, "geoCheck", result);
      return result;
    } finally {
      this.busy = false;
    }
  }
  install() {
    if (this.busy) throw Error("数据库任务正在进行");
    if (!getConfig(this.db, "maxmind")) throw Error("请先设置下载凭据");
    this.busy = true;
    this.state = { phase: "开始下载", progress: 0 };
    this.task = this.perform()
      .catch((error) => {
        this.state = {
          phase: error.publicMessage
            ? error.publicMessage + " 已保留原数据库。"
            : "更新失败，保留原数据库；请检查下载凭据、网络及磁盘空间",
          progress: 0,
        };
      })
      .finally(() => {
        this.busy = false;
      });
  }
  async perform() {
    const id = token(),
      stage = path.join(this.dir, "stage-" + id),
      destination = path.join(this.dir, "db-" + id);
    mkdirSync(stage);
    const metadata = {},
      readers = {};
    let committed = false;
    try {
      for (const [index, name] of editions.entries()) {
        this.state = { phase: "下载 " + name, progress: index * 45 };
        const r = await this.request(name),
          archive = path.join(stage, name + ".tar.gz");
        let size = 0;
        await pipeline(
          Readable.fromWeb(r.body),
          new Transform({
            transform: (chunk, enc, cb) => {
              size += chunk.length;
              this.state.downloadedBytes = size;
              cb(size > 160 * 1024 ** 2 ? Error("压缩包过大") : null, chunk);
            },
          }),
          createWriteStream(archive, { flags: "wx" }),
        );
        this.state.phase = "校验 " + name;
        const checksumResponse = await this.request(name, {
          suffix: "tar.gz.sha256",
        });
        let checksumText = "";
        for await (const c of checksumResponse.body) {
          checksumText += Buffer.from(c).toString();
          if (checksumText.length > 4096) throw Error("校验文件过大");
        }
        const expected = checksumText
          .match(/\b[a-fA-F0-9]{64}\b/)?.[0]
          ?.toLowerCase();
        const hash = createHash("sha256");
        for await (const chunk of createReadStream(archive)) hash.update(chunk);
        if (!expected || hash.digest("hex") !== expected)
          throw Error("校验失败");
        let expanded = 0;
        await pipeline(
          createReadStream(archive),
          createGunzip(),
          new Transform({
            transform(chunk, enc, cb) {
              expanded += chunk.length;
              cb(
                expanded > 256 * 1024 ** 2 ? Error("解压数据过大") : null,
                chunk,
              );
            },
          }),
          tar.x({
            cwd: stage,
            strip: 1,
            strict: true,
            filter: (p, e) =>
              e.type === "File" &&
              new RegExp("^[^/]+/" + name + "\\.mmdb$").test(p),
          }),
        );
        const file = path.join(stage, name + ".mmdb");
        readers[name] = new maxmind.Reader(readFileSync(file));
        if (readers[name].metadata.databaseType !== name)
          throw Error("数据库类型错误");
        metadata[name] = {
          bytes: statSync(file).size,
          modified: r.headers.get("last-modified"),
          buildEpoch: readers[name].metadata.buildEpoch,
        };
        rmSync(archive);
      }
      this.state = { phase: "安装数据库", progress: 95 };
      renameSync(stage, destination);
      const current = {
        directory: path.basename(destination),
        installedAt: Date.now(),
        databases: metadata,
      };
      writeFileSync(
        path.join(this.dir, "current.next.json"),
        JSON.stringify(current),
      );
      renameSync(
        path.join(this.dir, "current.next.json"),
        path.join(this.dir, "current.json"),
      );
      const previous = this.current;
      this.current = current;
      this.readers = readers;
      this.cache.clear();
      committed = true;
      if (previous?.directory && /^db-[a-f0-9]{48}$/.test(previous.directory))
        rmSync(path.join(this.dir, previous.directory), {
          recursive: true,
          force: true,
        });
      this.state = { phase: "安装成功，压缩包及旧数据库已清理", progress: 100 };
    } finally {
      rmSync(stage, { recursive: true, force: true });
      if (!committed) rmSync(destination, { recursive: true, force: true });
    }
  }
  lookup(ip) {
    if (this.cache.has(ip)) return this.cache.get(ip);
    const empty = {
      country: "未知",
      region: "未知",
      city: "未知",
      organization: "未知",
    };
    let result = empty;
    if (!isIP(ip)) return empty;
    if (ip === "::1" || /^127\./.test(ip))
      result = { ...empty, country: "本机" };
    else if (
      /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
        ip,
      ) ||
      /^(f[cd]|fe[89ab])/i.test(ip) ||
      ip === "::"
    )
      result = { ...empty, country: "内网 / 保留地址" };
    else
      try {
        const city = this.readers["GeoLite2-City"]?.get(ip),
          asn = this.readers["GeoLite2-ASN"]?.get(ip),
          name = (x) => x?.names?.["zh-CN"] || x?.names?.en || "未知";
        result = {
          country: name(city?.country),
          countryCode: city?.country?.iso_code || null,
          region: name(city?.subdivisions?.[0]),
          city: name(city?.city),
          organization: asn?.autonomous_system_organization || "未知",
          asn: asn?.autonomous_system_number || null,
        };
      } catch {}
    if (this.cache.size >= 10000)
      this.cache.delete(this.cache.keys().next().value);
    this.cache.set(ip, result);
    return result;
  }
}
