// remnawave-admin: мелкие интеракции (confirm на опасных действиях, копирование, flash)
document.addEventListener("DOMContentLoaded", () => {
  // confirm-формы: <form data-confirm="текст">
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => {
      if (!window.confirm(f.getAttribute("data-confirm") || "Вы уверены?")) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    });
  });
  // кнопки-копирование: <button class="copy" data-copy="#el-id">
  document.querySelectorAll(".copy").forEach((b) => {
    b.addEventListener("click", async (e) => {
      e.preventDefault();
      const sel = b.getAttribute("data-copy");
      const el = sel ? document.querySelector(sel) : null;
      const text = el ? (el.textContent || "").trim() : "";
      try {
        await navigator.clipboard.writeText(text);
        const old = b.textContent;
        b.textContent = "скопировано";
        setTimeout(() => (b.textContent = old), 1500);
      } catch {
        window.prompt("Скопируйте вручную:", text);
      }
    });
  });
  // авто-скрытие flash
  const fl = document.querySelector(".flash");
  if (fl) setTimeout(() => fl.remove(), 9000);
});
