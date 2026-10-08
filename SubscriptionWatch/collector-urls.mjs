export function validateCollectorUrls(value) {
  if (!Array.isArray(value) || value.length > 5)
    throw Error("风控后台地址须为不超过5个HTTPS地址");
  const urls = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !entry.trim() || entry.length > 255)
      throw Error("风控后台地址格式错误");
    let url;
    try {
      url = new URL(entry.trim());
    } catch {
      throw Error("风控后台地址格式错误");
    }
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw Error("风控后台地址须为HTTPS根地址，不能带路径、参数或账号密码");
    if (!urls.includes(url.origin)) urls.push(url.origin);
  }
  return urls;
}
