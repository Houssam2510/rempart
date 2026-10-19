import DOMPurify from "dompurify";

export function renderComment(el, comment) {
  // rempart-safe: CODE-XSS-SINK
  el.innerHTML = DOMPurify.sanitize(comment.body);
}

export function renderSearch(el) {
  const q = new URLSearchParams(location.search).get("q");
  // rempart-expect: CODE-XSS-SINK
  el.innerHTML = "Results for " + q;
}

export function renderCount(el, items) {
  // rempart-safe: CODE-XSS-SINK
  el.innerHTML = `<b>${items.length}</b> results`;
}

export function saveSession(token) {
  // rempart-expect: CODE-TOKEN-LOCALSTORAGE
  localStorage.setItem("access_token", token);
}
