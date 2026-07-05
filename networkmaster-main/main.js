const revealItems = document.querySelectorAll(".reveal");

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
      }
    });
  },
  { threshold: 0.16 }
);

revealItems.forEach((item, index) => {
  item.style.transitionDelay = `${Math.min(index * 55, 260)}ms`;
  observer.observe(item);
});

const launcher = document.getElementById("toolLauncher");
const launchInput = document.getElementById("launchInput");
const launchTool = document.getElementById("launchTool");

if (launcher && launchInput && launchTool) {
  launcher.addEventListener("submit", (event) => {
    event.preventDefault();

    const target = launchTool.value;
    const value = launchInput.value.trim();

    if (!value) {
      window.location.href = target;
      return;
    }

    const param = encodeURIComponent(value);
    window.location.href = `${target}?q=${param}`;
  });
}

const canvas = document.getElementById("networkCanvas");
const ctx = canvas ? canvas.getContext("2d") : null;

if (canvas && ctx) {
  const nodes = [];
  const count = 42;

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;

    canvas.width = rect.width * ratio;
    canvas.height = rect.height * ratio;

    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function createNodes() {
    nodes.length = 0;

    const rect = canvas.getBoundingClientRect();

    for (let i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * rect.width,
        y: Math.random() * rect.height,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
        r: Math.random() * 2.4 + 1.4,
      });
    }
  }

  function draw() {
    const rect = canvas.getBoundingClientRect();
    ctx.clearRect(0, 0, rect.width, rect.height);

    for (const node of nodes) {
      node.x += node.vx;
      node.y += node.vy;

      if (node.x < 0 || node.x > rect.width) node.vx *= -1;
      if (node.y < 0 || node.y > rect.height) node.vy *= -1;
    }

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 118) {
          const alpha = 1 - distance / 118;
          ctx.strokeStyle = `rgba(79, 70, 229, ${alpha * 0.18})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const node of nodes) {
      const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, node.r * 5);
      gradient.addColorStop(0, "rgba(6, 182, 212, 0.95)");
      gradient.addColorStop(1, "rgba(109, 93, 252, 0)");

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r * 5, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = "rgba(7, 23, 53, 0.85)";
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(draw);
  }

  resizeCanvas();
  createNodes();
  draw();

  window.addEventListener("resize", () => {
    resizeCanvas();
    createNodes();
  });
}

// HOME LANGUAGE SWITCHER START
(function () {
  const languageSwitcher = document.getElementById("languageSwitcher");
  const languageTrigger = document.getElementById("languageTrigger");
  const languageAltLink = document.getElementById("languageAltLink");

  if (!languageSwitcher || !languageTrigger || !languageAltLink) return;

  function closeLanguageMenu() {
    languageSwitcher.classList.remove("is-open");
    languageTrigger.setAttribute("aria-expanded", "false");
  }

  languageTrigger.addEventListener("click", function (event) {
    event.preventDefault();
    event.stopPropagation();

    const isOpen = languageSwitcher.classList.toggle("is-open");
    languageTrigger.setAttribute("aria-expanded", String(isOpen));
  });

  document.addEventListener("click", function (event) {
    if (!languageSwitcher.contains(event.target)) {
      closeLanguageMenu();
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeLanguageMenu();
    }
  });

  languageAltLink.addEventListener("click", function (event) {
    event.preventDefault();
    closeLanguageMenu();
  });
})();
// HOME LANGUAGE SWITCHER END

