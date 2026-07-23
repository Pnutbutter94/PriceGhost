// #B346 medium: scrapeWithBrowser() launched an unbounded number of headless
// Chromium instances per concurrent request — resource-exhaustion risk on the
// i5-4210U/8GB host. Simple counting semaphore, no new dependency.
const MAX_CONCURRENT = 2;
let active = 0;
const queue = [];

function acquire() {
  return new Promise((resolve) => {
    const tryAcquire = () => {
      if (active < MAX_CONCURRENT) {
        active++;
        resolve(() => {
          active--;
          const next = queue.shift();
          if (next) next();
        });
      } else {
        queue.push(tryAcquire);
      }
    };
    tryAcquire();
  });
}

module.exports = { acquire };
