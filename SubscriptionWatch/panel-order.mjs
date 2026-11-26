import { transaction } from "./model.mjs";

export function initPanelOrder(db) {
  if (
    !db
      .prepare("PRAGMA table_info(panels)")
      .all()
      .some((c) => c.name === "sort_order")
  )
    db.exec("ALTER TABLE panels ADD COLUMN sort_order INTEGER");
}
export function savePanelOrder(db, owner, ids) {
  if (
    !Array.isArray(ids) ||
    ids.length > 100 ||
    ids.some((id) => !Number.isSafeInteger(id) || id < 1) ||
    new Set(ids).size !== ids.length
  )
    throw Object.assign(Error("面板顺序无效，请刷新后重试"), { status: 400 });
  return transaction(db, () => {
    const own = db
      .prepare("SELECT id FROM panels WHERE owner=?")
      .all(owner)
      .map((p) => p.id);
    if (own.length !== ids.length || ids.some((id) => !own.includes(id)))
      throw Object.assign(Error("面板列表已变化，请刷新后重新排序"), {
        status: 409,
      });
    const update = db.prepare(
      "UPDATE panels SET sort_order=? WHERE owner=? AND id=?",
    );
    ids.forEach((id, i) => update.run(i + 1, owner, id));
    return { ok: true };
  });
}
