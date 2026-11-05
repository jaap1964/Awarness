(() => {
  const marker = document.querySelector("#tracking");
  if (!marker) return;
  fetch("/r/" + encodeURIComponent(marker.dataset.token) + "/confirm", {
    method: "POST",
    credentials: "omit",
    headers: {"Content-Type": "text/plain"},
    body: "confirmed",
    keepalive: true
  }).catch(() => {});
})();
