const message = document.querySelector("#message");
const address = document.querySelector("#subscription-address");
if (address) address.onclick = () => address.select();
for (const button of document.querySelectorAll("[data-copy]"))
  button.onclick = async () => {
    const text =
      button.dataset.copy === "page" ? location.href : address?.value;
    if (!text) return;
    button.disabled = true;
    let copied = false;
    try {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {}
      if (!copied) {
        const input = document.createElement("textarea");
        input.value = text;
        input.readOnly = true;
        input.style.position = "fixed";
        input.style.left = "-9999px";
        document.body.append(input);
        try {
          input.select();
          copied = document.execCommand("copy") === true;
        } catch {
        } finally {
          input.remove();
        }
      }
      message.dataset.error = String(!copied);
      message.setAttribute("role", copied ? "status" : "alert");
      message.textContent = copied
        ? "已复制，请粘贴到浏览器或 Shadowrocket 中。"
        : "浏览器未允许复制，请长按地址栏复制此页链接，或展开订阅地址后手动复制。";
      if (!copied && address) {
        address.closest("details").open = true;
        address.select();
      }
    } finally {
      button.disabled = false;
    }
  };
