import { defaults, transaction } from "./model.mjs";
import { requestCounts } from "./review.mjs";

export function clientStatusByUsers(db, panel, uids, now = Date.now()) {
  const ids = [
    ...new Set(uids.filter((uid) => Number.isSafeInteger(uid) && uid > 0)),
  ];
  if (!ids.length) return new Map();
  const dailyLimit = { ...defaults, ...JSON.parse(panel.rules) }.dailyLimit;
  const subjects = db
    .prepare(
      `SELECT s.uid,s.email,s.white,s.verified,s.daily_reset_at,COALESCE(r.active,0) suspicious
     FROM subjects s LEFT JOIN risks r ON r.panel=s.panel AND r.uid=s.uid
     WHERE s.panel=? AND s.uid IN (${ids.map(() => "?").join(",")})`,
    )
    .all(panel.id, ...ids);
  return new Map(
    subjects.map((s) => {
      const counts = requestCounts(db, panel.id, s.uid, now, s.daily_reset_at);
      return [
        s.uid,
        {
          email: s.email,
          verified: !!s.verified,
          white: !!s.white,
          suspicious: !!s.suspicious,
          dailyCount: counts.total,
          ipWhitelistCount: counts.ipWhitelist,
          unclassifiedCount: counts.unclassified,
          dailyLimit,
          dailyLimitReached: counts.total >= dailyLimit,
          nextRequestNumber: counts.total + 1,
        },
      ];
    }),
  );
}

export function clientStatusRows(
  db,
  panel,
  search = "",
  page = 1,
  now = Date.now(),
) {
  const q = search.trim().slice(0, 254);
  const where =
    "s.panel=? AND s.verified=1" +
    (q ? " AND (CAST(s.uid AS TEXT)=? OR s.email LIKE ?)" : "");
  const args = q ? [panel.id, q, `%${q}%`] : [panel.id];
  const limit = 50;
  const offset = (page - 1) * limit;
  const limitCount = { ...defaults, ...JSON.parse(panel.rules) }.dailyLimit;
  const subjects = db
    .prepare(
      `SELECT s.uid,s.email,s.white,s.daily_reset_at,COALESCE(r.active,0) suspicious
     FROM subjects s LEFT JOIN risks r ON r.panel=s.panel AND r.uid=s.uid
     WHERE ${where}
     ORDER BY s.uid DESC LIMIT ? OFFSET ?`,
    )
    .all(...args, limit, offset);
  const lastReview = db.prepare(
    "SELECT MAX(ts) ts FROM review_decisions WHERE panel=? AND uid=?",
  );
  const lastVisit = db.prepare(
    "SELECT MAX(ts) ts FROM visits WHERE panel=? AND uid=?",
  );
  return {
    page,
    total: db
      .prepare(`SELECT COUNT(*) n FROM subjects s WHERE ${where}`)
      .get(...args).n,
    dailyLimit: limitCount,
    rows: subjects.map((s) => {
      const counts = requestCounts(db, panel.id, s.uid, now, s.daily_reset_at);
      return {
        uid: s.uid,
        email: s.email,
        white: !!s.white,
        suspicious: !!s.suspicious,
        dailyCount: counts.total,
        ipWhitelistCount: counts.ipWhitelist,
        unclassifiedCount: counts.unclassified,
        dailyLimitReached: counts.total >= limitCount,
        nextRequestNumber: counts.total + 1,
        lastRequestAt: Math.max(
          lastReview.get(panel.id, s.uid).ts || 0,
          lastVisit.get(panel.id, s.uid).ts || 0,
        ),
      };
    }),
  };
}

export function resetClientDailyCount(db, panel, uid, email, now = Date.now()) {
  if (!Number.isSafeInteger(uid) || uid < 1 || typeof email !== "string")
    throw Error("用户ID或邮箱无效");
  return transaction(db, () => {
    const subject = db
      .prepare("SELECT email,verified FROM subjects WHERE panel=? AND uid=?")
      .get(panel, uid);
    if (!subject?.verified || subject.email !== email)
      throw Error("用户ID与已采集邮箱不匹配，请刷新后重试");
    db.prepare(
      "UPDATE subjects SET daily_reset_at=? WHERE panel=? AND uid=?",
    ).run(now, panel, uid);
    db.prepare(
      "INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)",
    ).run(panel, uid, email, now, "重置24小时订阅次数", "[]");
    return { ok: true };
  });
}
