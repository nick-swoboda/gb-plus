"use strict";

export function createChatScroll(canvas, content) {
  let following = true;
  const bottom = () => Math.max(0, canvas.scrollHeight - canvas.clientHeight);
  function update() {
    if (following && canvas.clientHeight > 0) canvas.scrollTop = bottom();
  }
  canvas.addEventListener("scroll", () => {
    following = bottom() - Math.max(0, canvas.scrollTop) <= 32;
  }, { passive: true });
  const observer = new ResizeObserver(update);
  observer.observe(content);
  return {
    update,
    reset() {
      following = true;
      update();
    },
  };
}
