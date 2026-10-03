const labels = {
  "daily-limit": "超过每人 24 小时订阅请求上限",
  ua: "非指定客户端获取订阅",
  cloud: "云服务器 IP 获取订阅",
  blacklist: "黑名单 IP 获取订阅",
  "mainland-only": "来源 IP 不在中国大陆或白名单",
  cn60: "多个中国大陆 IP 获取订阅（短窗口）",
  cn720: "多个中国大陆 IP 获取订阅（长窗口）",
  foreign60: "多个非中国大陆 IP 获取订阅（短窗口）",
  foreign720: "多个非中国大陆 IP 获取订阅（长窗口）",
};

export function describeReviewCodes(codes, activeReasons = []) {
  const original = [...new Set(activeReasons.map((reason) => reason?.label).filter(Boolean))];
  return [...new Set(codes.map((code) =>
    code === "active-risk"
      ? original.length
        ? `已有可疑标记（原触发：${original.join("、")}）`
        : "已有可疑标记（原触发规则未保存）"
      : labels[code] || "其他风控规则（规则名称未保存）",
  ))];
}
