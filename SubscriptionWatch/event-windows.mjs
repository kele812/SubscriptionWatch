// Display windows are independent of quota buckets. Raw visits remain authoritative.
export function initEventWindows(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS event_window_state(
    panel INTEGER NOT NULL, uid INTEGER NOT NULL, minutes INTEGER NOT NULL,
    last_id INTEGER NOT NULL, amount INTEGER NOT NULL, PRIMARY KEY(panel,uid));
    CREATE TABLE IF NOT EXISTS event_windows(
    panel INTEGER NOT NULL, uid INTEGER NOT NULL, first_id INTEGER NOT NULL,
    latest_id INTEGER NOT NULL, started INTEGER NOT NULL, ended INTEGER NOT NULL,
    amount INTEGER NOT NULL, PRIMARY KEY(panel,first_id));
    CREATE INDEX IF NOT EXISTS event_window_user ON event_windows(panel,uid);`);
}

export function syncEventWindows(db, panel, minutes) {
  const users = db
    .prepare(
      `SELECT uid,MAX(id) last_id,COUNT(*) amount FROM visits
    WHERE panel=? GROUP BY uid`,
    )
    .all(panel);
  const states = new Map(
    db
      .prepare("SELECT * FROM event_window_state WHERE panel=?")
      .all(panel)
      .map((r) => [r.uid, r]),
  );
  const remove = db.prepare(
    "DELETE FROM event_windows WHERE panel=? AND uid=?",
  );
  const save = db.prepare(
    "INSERT OR REPLACE INTO event_windows VALUES(?,?,?,?,?,?,?)",
  );
  const remember = db.prepare(
    `INSERT OR REPLACE INTO event_window_state VALUES(?,?,?,?,?)`,
  );
  db.exec("SAVEPOINT event_display_sync");
  try {
    for (const u of users) {
      const old = states.get(u.uid);
      states.delete(u.uid);
      if (
        old?.minutes === minutes &&
        old.last_id === u.last_id &&
        old.amount === u.amount
      )
        continue;
      let rows, group;
      if (
        old?.minutes === minutes &&
        u.last_id > old.last_id &&
        u.amount > old.amount
      ) {
        rows = db
          .prepare(
            "SELECT id,ts FROM visits WHERE panel=? AND uid=? AND id>? ORDER BY ts,id",
          )
          .all(panel, u.uid, old.last_id);
        const last = db
          .prepare(
            "SELECT * FROM event_windows WHERE panel=? AND uid=? ORDER BY started DESC,first_id DESC LIMIT 1",
          )
          .get(panel, u.uid);
        if (
          last &&
          rows.length === u.amount - old.amount &&
          rows[0].ts >= last.ended
        ) {
          group = {
            first: last.first_id,
            latest: last.latest_id,
            started: last.started,
            ended: last.ended,
            amount: last.amount,
          };
        } else rows = null;
      }
      if (!rows) {
        remove.run(panel, u.uid);
        rows = db
          .prepare(
            "SELECT id,ts FROM visits WHERE panel=? AND uid=? ORDER BY ts,id",
          )
          .all(panel, u.uid);
      }
      const flush = () => {
        if (group)
          save.run(
            panel,
            u.uid,
            group.first,
            group.latest,
            group.started,
            group.ended,
            group.amount,
          );
      };
      for (const r of rows) {
        if (
          !group ||
          minutes === 0 ||
          r.ts - group.started >= minutes * 60000
        ) {
          flush();
          group = {
            first: r.id,
            latest: r.id,
            started: r.ts,
            ended: r.ts,
            amount: 1,
          };
        } else {
          group.latest = r.id;
          group.ended = r.ts;
          group.amount++;
        }
      }
      flush();
      remember.run(panel, u.uid, minutes, u.last_id, u.amount);
    }
    for (const uid of states.keys()) {
      remove.run(panel, uid);
      db.prepare("DELETE FROM event_window_state WHERE panel=? AND uid=?").run(
        panel,
        uid,
      );
    }
    db.exec("RELEASE event_display_sync");
  } catch (error) {
    db.exec("ROLLBACK TO event_display_sync; RELEASE event_display_sync");
    throw error;
  }
}

export const windowVisitsSql = `(SELECT v.*,w.started AS windowStarted,w.ended AS windowEnded,
  w.amount AS windowRequests FROM event_windows w JOIN visits v ON v.id=w.latest_id AND v.panel=w.panel)`;
