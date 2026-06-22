const WATCHER_STATE = { OFF: 0, PENDING: 1, ON: 2 };
const POLL_INTERVAL = 1500; 
const polls = {}; 


function updateWatcherButton(btn, state) {
  const spinner = btn.querySelector(".spinner-border");
  if (!btn) return;

  btn.disabled = false;
  spinner?.classList.add("d-none");
	console.log(state);
  switch (state) {
    case WATCHER_STATE.ON:
      btn.className = `btn btn-sm btn-success watcher-btn`;
      btn.dataset.state = "2";
      btn.innerText = `${btn.dataset.type.toUpperCase()} ON`;
      break;
    case WATCHER_STATE.OFF:
      btn.className = `btn btn-sm btn-secondary watcher-btn`;
      btn.dataset.state = "0";
      btn.innerText = `${btn.dataset.type.toUpperCase()} OFF`;
      break;
    case WATCHER_STATE.PENDING:
      btn.className = `btn btn-sm btn-warning watcher-btn`;
      btn.dataset.state = "1";
      btn.innerText = `${btn.dataset.type.toUpperCase()} PENDING`;
      btn.disabled = true;
      spinner?.classList.remove("d-none");
      break;
    default:
      btn.className = `btn btn-sm btn-danger watcher-btn`;
      btn.innerText = `${btn.dataset.type.toUpperCase()} UNKNOWN`;
  }
}


function pollWatcher(type, uuid, btn) {
  fetch(`/watcher/status/${uuid}/${type}`, { cache: "no-store" })
    .then(r => r.json())
    .then(data => {
      updateWatcherButton(btn, data.state);
      const key = `${type}_${uuid}`;
      if (data.state !== WATCHER_STATE.PENDING && polls[key]) {
        clearInterval(polls[key]);
        polls[key] = null;
      }
    })
    .catch(err => console.error(`Watcher poll error (${type}):`, err));
}


function toggleWatcher(type, uuid, btn) {
  fetch(`/watcher/toggle/${uuid}/${type}`, { cache: "no-store" })
    .then(() => {
      updateWatcherButton(btn, WATCHER_STATE.PENDING);
      const key = `${type}_${uuid}`;
      if (!polls[key]) {
        polls[key] = setInterval(() => pollWatcher(type, uuid, btn), POLL_INTERVAL);
      }
    })
    .catch(err => console.error(`Watcher toggle error (${type}):`, err));
}


document.addEventListener("click", function (e) {
  const btn = e.target.closest(".watcher-btn");
  if (!btn) return;

  const type = btn.dataset.type;
  const uuid = btn.dataset.uuid;
  if (!type || !uuid) return;

  toggleWatcher(type, uuid, btn);
});


function initWatchers() {
  document.querySelectorAll(".watcher-btn").forEach(btn => {
    const type = btn.dataset.type;
    const uuid = btn.dataset.uuid;
    if (!type || !uuid) return;
    pollWatcher(type, uuid, btn);
  });
}


document.addEventListener("DOMContentLoaded", initWatchers);
document.addEventListener("shown.bs.modal", initWatchers);
