const form = document.querySelector("#authForm"),
  error = document.querySelector("#authError"),
  submit = document.querySelector("#authSubmit");
let setup = false;
fetch("/api/setup/status", { cache: "no-store" })
  .then(async (r) => {
    if (!r.ok) throw Error("无法检查站点状态，请刷新重试");
    const s = await r.json();
    setup = s.needsSetup;
    document.querySelector("#authTitle").textContent = setup
      ? "首次设置登录账号"
      : "登录";
    document.querySelector("#authHelp").textContent = setup
      ? "设置一个后台登录账号和密码。没有注册入口，也不需要安装验证码。"
      : "请输入账号密码。登录后才能访问后台。";
    document.querySelector("#confirmField").hidden = !setup;
    form.elements.confirmPassword.required = setup;
    form.elements.password.minLength = setup ? 12 : 1;
    submit.textContent = setup ? "保存并进入后台" : "登录";
    submit.disabled = false;
  })
  .catch((e) => {
    error.textContent = e.message;
  });
form.onsubmit = async (e) => {
  e.preventDefault();
  submit.disabled = true;
  error.textContent = "";
  try {
    const response = await fetch(setup ? "/api/setup" : "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Watch-Request": "1" },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const b = await response.json();
    if (!response.ok) throw Error(b.error || "登录失败");
    form.reset();
    location.replace("/");
  } catch (e) {
    error.textContent = e.message;
    submit.disabled = false;
  }
};
addEventListener("pageshow", (e) => {
  if (e.persisted) location.reload();
});
