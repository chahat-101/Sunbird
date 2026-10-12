// Loaded in <head>, before anything paints, so a saved theme never flashes
// the other one first. With nothing saved, the CSS follows the device.
(function () {
  'use strict';
  const KEY = 'sunbird.theme';
  const root = document.documentElement;

  function saved() {
    try {
      const value = localStorage.getItem(KEY);
      return value === 'light' || value === 'dark' ? value : 'system';
    } catch (_) {
      return 'system';
    }
  }

  function apply(choice) {
    if (choice === 'system') root.removeAttribute('data-theme');
    else root.dataset.theme = choice;
    for (const button of document.querySelectorAll('[data-theme-choice]')) {
      button.setAttribute('aria-pressed', String(button.dataset.themeChoice === choice));
    }
  }

  apply(saved());

  document.addEventListener('DOMContentLoaded', () => {
    apply(saved());
    for (const button of document.querySelectorAll('[data-theme-choice]')) {
      button.addEventListener('click', () => {
        const choice = button.dataset.themeChoice;
        try {
          if (choice === 'system') localStorage.removeItem(KEY);
          else localStorage.setItem(KEY, choice);
        } catch (_) { /* this page only */ }
        apply(choice);
      });
    }

    // The sign-in page loads no other script, so its copy button lives here.
    for (const button of document.querySelectorAll('[data-copy]')) {
      const source = document.getElementById(button.dataset.copy);
      const note = document.querySelector('[data-copy-status]');
      button.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(source.textContent);
          note.dataset.state = 'done';
          note.textContent = 'Copied.';
        } catch (_) {
          window.getSelection().selectAllChildren(source);
          note.dataset.state = 'error';
          note.textContent = 'Could not copy automatically. It is selected: copy it with your device’s copy command.';
        }
      });
    }
  });
})();
