const message = document.querySelector("#message");
for (const button of document.querySelectorAll('[data-copy="page"]'))
  button.onclick = async () => {
    const text = location.href;
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
        ? "已复制此页链接，请粘贴到 Safari 或其他浏览器中。"
        : "浏览器未允许复制，请长按地址栏复制此页链接。";
    } finally {
      button.disabled = false;
    }
  };
