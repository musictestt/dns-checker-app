document.addEventListener("DOMContentLoaded", () => {
  const switchers = document.querySelectorAll(".language-switcher");
  const currentPath = window.location.pathname || "/";
  const isFaPage = document.body.classList.contains("fa-page");

  function closeAll() {
    switchers.forEach(sw => {
      sw.classList.remove("is-open");
      const trigger = sw.querySelector(".language-trigger");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  }

  function setLanguageText(container, label, flag) {
    if (!container) return;

    const flagBox = container.querySelector(".flag-box");
    if (flagBox) flagBox.textContent = flag;

    const spans = Array.from(container.querySelectorAll("span"));
    const textSpan = spans.find(span => !span.classList.contains("flag-box"));

    if (textSpan) {
      textSpan.textContent = label;
    } else {
      const icon = container.querySelector(".nav-icon");
      const newSpan = document.createElement("span");
      newSpan.textContent = label;
      if (icon) {
        container.insertBefore(newSpan, icon);
      } else {
        container.appendChild(newSpan);
      }
    }
  }

  let targetLangPath;

  if (isFaPage) {
    // /fa/dhnjh -> /dhnjh
    targetLangPath = currentPath.replace(/^\/fa(?=\/|$)/, "");
    if (!targetLangPath) targetLangPath = "/";
  } else {
    // /dhnjh -> /fa/dhnjh
    targetLangPath = currentPath === "/" ? "/fa/" : `/fa${currentPath}`;
  }

  switchers.forEach(sw => {
    const trigger = sw.querySelector(".language-trigger");
    const menu = sw.querySelector(".language-menu");
    const option = sw.querySelector(".language-menu a, a.language-option");

    if (isFaPage) {
      setLanguageText(trigger, "Persian", "FA");
      setLanguageText(option, "English", "US");
    } else {
      setLanguageText(trigger, "English", "US");
      setLanguageText(option, "Persian", "FA");
    }

    if (option) {
      option.setAttribute("href", targetLangPath);
    }

    if (!trigger || !menu) return;

    trigger.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();

      const isOpen = sw.classList.contains("is-open");
      closeAll();

      if (!isOpen) {
        sw.classList.add("is-open");
        trigger.setAttribute("aria-expanded", "true");
      }
    });

    menu.addEventListener("click", event => {
      event.stopPropagation();
    });
  });

  document.addEventListener("click", closeAll);

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeAll();
  });
});
