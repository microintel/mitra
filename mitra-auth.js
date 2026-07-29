/*!
 * Mitra Auth — client-side only authentication, backed by IndexedDB.
 * Database name: "mitrami"
 *
 * There is NO server / backend involved. Everything (accounts, sessions,
 * profile data) lives in the browser's IndexedDB, scoped to whatever
 * origin this file is served from.
 *
 * FUTURE FIREBASE MIGRATION
 * --------------------------------------------------------------------
 * Every public method below (register, login, logout, getCurrentUser,
 * updateProfile, updatePassword, onAuthChange) is written as a Promise
 * that resolves to a plain "public user" object: { email, name, ... }.
 * When Google Firebase Auth is wired in later, the *call sites* in
 * login.html / register.html / profile.html / mitra-dashboard.html do
 * not need to change — only the internals of these functions do. E.g.:
 *
 *   register: function(name, email, password){
 *     return firebase.auth().createUserWithEmailAndPassword(email, password)
 *       .then(function(cred){
 *         return firebase.auth().currentUser.updateProfile({displayName:name});
 *       })
 *       .then(...)
 *   }
 *
 * Keep the same method names/signatures and the rest of the app keeps
 * working unchanged.
 * --------------------------------------------------------------------
 */
(function (global) {
  "use strict";

  var DB_NAME = "mitrami";
  var DB_VERSION = 2;
  var STORE_USERS = "users";
  var STORE_SESSION = "session";
  var STORE_SETTINGS = "settings";
  var SESSION_ID = "current";
  var THEME_ID = "theme";
  var ACCENT_ID = "accent";
  var DEFAULT_ACCENT = "emerald";
  /** Every accent is picked for a specific psychological effect, not just
   *  looks — shown in the picker so the choice feels intentional. Emerald
   *  is the default because growth-green is the same "go / correct /
   *  progress" cue that makes streak-and-habit apps feel rewarding to
   *  keep up with day after day. */
  var ACCENTS = [
    { id: "emerald",    name: "Emerald",    effect: "",    swatch: "#149164" },
    { id: "ocean",      name: "Ocean",      effect: "",   swatch: "#1477A6" },
    { id: "plum",       name: "Plum",       effect: "", swatch: "#8B4FBF" },
    { id: "terracotta", name: "Terracotta", effect: "",   swatch: "#C1592D" },
    { id: "berry",      name: "Berry",      effect: "",     swatch: "#B0295A" },
    { id: "slate",      name: "Slate",      effect: "",      swatch: "#445048" }
  ];

  var authChangeListeners = [];
  var themeChangeListeners = [];
  var accentChangeListeners = [];
  var themeChannel = (typeof BroadcastChannel !== "undefined") ? new BroadcastChannel("mitrami-theme") : null;
  if (themeChannel) {
    themeChannel.onmessage = function (e) { notifyThemeChange(e.data); };
  }
  var accentChannel = (typeof BroadcastChannel !== "undefined") ? new BroadcastChannel("mitrami-accent") : null;
  if (accentChannel) {
    accentChannel.onmessage = function (e) { notifyAccentChange(e.data); };
  }

  function openDB() {
    return new Promise(function (resolve, reject) {
      if (!global.indexedDB) {
        reject(new Error("This browser does not support IndexedDB, which Mitra needs to sign you in."));
        return;
      }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains(STORE_USERS)) {
          db.createObjectStore(STORE_USERS, { keyPath: "email" });
        }
        if (!db.objectStoreNames.contains(STORE_SESSION)) {
          db.createObjectStore(STORE_SESSION, { keyPath: "id" });
        }
        if (!db.objectStoreNames.contains(STORE_SETTINGS)) {
          db.createObjectStore(STORE_SETTINGS, { keyPath: "id" });
        }
      };
      req.onsuccess = function (e) { resolve(e.target.result); };
      req.onerror = function (e) { reject(e.target.error || new Error("Could not open the local database.")); };
    });
  }

  function store(db, name, mode) {
    return db.transaction(name, mode).objectStore(name);
  }

  function reqToPromise(req) {
    return new Promise(function (resolve, reject) {
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function randomHex(byteLen) {
    var arr = new Uint8Array(byteLen);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  function hashPassword(password, salt) {
    var enc = new TextEncoder();
    return crypto.subtle.digest("SHA-256", enc.encode(salt + ":" + password)).then(function (buf) {
      return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
  }

  function getUser(db, email) {
    return reqToPromise(store(db, STORE_USERS, "readonly").get(email)).then(function (u) { return u || null; });
  }

  function putUser(db, user) {
    return reqToPromise(store(db, STORE_USERS, "readwrite").put(user));
  }

  function getSession(db) {
    return reqToPromise(store(db, STORE_SESSION, "readonly").get(SESSION_ID)).then(function (s) { return s || null; });
  }

  function setSession(db, email) {
    return reqToPromise(store(db, STORE_SESSION, "readwrite").put({ id: SESSION_ID, email: email, loggedInAt: new Date().toISOString() }));
  }

  function clearSession(db) {
    return reqToPromise(store(db, STORE_SESSION, "readwrite").delete(SESSION_ID));
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function publicUser(user) {
    if (!user) return null;
    var copy = {};
    for (var k in user) {
      if (k === "passwordHash" || k === "salt") continue;
      copy[k] = user[k];
    }
    return copy;
  }

  function notifyAuthChange(user) {
    authChangeListeners.forEach(function (fn) {
      try { fn(user); } catch (e) { /* listener errors shouldn't break auth */ }
    });
  }

  function notifyThemeChange(theme) {
    themeChangeListeners.forEach(function (fn) {
      try { fn(theme); } catch (e) { /* listener errors shouldn't break theme switching */ }
    });
  }

  function notifyAccentChange(accent) {
    accentChangeListeners.forEach(function (fn) {
      try { fn(accent); } catch (e) { /* listener errors shouldn't break accent switching */ }
    });
  }

  var MitraAuth = {
    DB_NAME: DB_NAME,

    /** Create a new local account and immediately sign the user in. */
    register: function (name, email, password) {
      name = (name || "").trim();
      email = (email || "").trim().toLowerCase();

      if (!name) return Promise.reject(new Error("Please enter your name."));
      if (!isValidEmail(email)) return Promise.reject(new Error("Please enter a valid email address."));
      if (!password || password.length < 6) return Promise.reject(new Error("Password must be at least 6 characters."));

      return openDB().then(function (db) {
        return getUser(db, email).then(function (existing) {
          if (existing) throw new Error("An account with this email already exists. Try logging in instead.");
          var salt = randomHex(16);
          return hashPassword(password, salt).then(function (hash) {
            var user = {
              email: email,
              name: name,
              passwordHash: hash,
              salt: salt,
              provider: "password",
              avatarLetter: name.charAt(0).toUpperCase(),
              level: 1,
              xp: 0,
              streak: 0,
              wordsLearned: 0,
              createdAt: new Date().toISOString()
            };
            return putUser(db, user)
              .then(function () { return setSession(db, email); })
              .then(function () {
                var pub = publicUser(user);
                notifyAuthChange(pub);
                return pub;
              });
          });
        });
      });
    },

    /** Sign in with an existing local account. */
    login: function (email, password) {
      email = (email || "").trim().toLowerCase();
      if (!isValidEmail(email)) return Promise.reject(new Error("Please enter a valid email address."));
      if (!password) return Promise.reject(new Error("Please enter your password."));

      return openDB().then(function (db) {
        return getUser(db, email).then(function (user) {
          if (!user) throw new Error("No account found with that email. Try creating one instead.");
          return hashPassword(password, user.salt).then(function (hash) {
            if (hash !== user.passwordHash) throw new Error("Incorrect password. Please try again.");
            return setSession(db, email).then(function () {
              var pub = publicUser(user);
              notifyAuthChange(pub);
              return pub;
            });
          });
        });
      });
    },

    /** Clear the current session. The account itself is untouched. */
    logout: function () {
      return openDB().then(function (db) {
        return clearSession(db).then(function () {
          notifyAuthChange(null);
        });
      });
    },

    /** Resolves to the signed-in user's public profile, or null. */
    getCurrentUser: function () {
      return openDB().then(function (db) {
        return getSession(db).then(function (session) {
          if (!session) return null;
          return getUser(db, session.email).then(publicUser);
        });
      });
    },

    /**
     * Guard for pages that require a signed-in user.
     * Redirects to `redirectTo` (default "login.html") if nobody is signed in.
     * Resolves with the user object if they are.
     */
    requireAuth: function (redirectTo) {
      redirectTo = redirectTo || "login.html";
      return MitraAuth.getCurrentUser().then(function (user) {
        if (!user) {
          window.location.href = redirectTo;
          return null;
        }
        return user;
      });
    },

    /** Merge `updates` into the signed-in user's stored profile. */
    updateProfile: function (email, updates) {
      email = (email || "").trim().toLowerCase();
      return openDB().then(function (db) {
        return getUser(db, email).then(function (user) {
          if (!user) throw new Error("User not found.");
          var merged = Object.assign({}, user, updates, { email: user.email });
          if (updates && updates.name) merged.avatarLetter = updates.name.trim().charAt(0).toUpperCase();
          return putUser(db, merged).then(function () {
            var pub = publicUser(merged);
            notifyAuthChange(pub);
            return pub;
          });
        });
      });
    },

    /** Change password after verifying the current one. */
    updatePassword: function (email, currentPassword, newPassword) {
      email = (email || "").trim().toLowerCase();
      if (!newPassword || newPassword.length < 6) return Promise.reject(new Error("New password must be at least 6 characters."));

      return openDB().then(function (db) {
        return getUser(db, email).then(function (user) {
          if (!user) throw new Error("User not found.");
          return hashPassword(currentPassword, user.salt).then(function (hash) {
            if (hash !== user.passwordHash) throw new Error("Your current password is incorrect.");
            return hashPassword(newPassword, user.salt).then(function (newHash) {
              user.passwordHash = newHash;
              return putUser(db, user);
            });
          });
        });
      });
    },

    /** Permanently delete the account and its session. */
    deleteAccount: function (email) {
      email = (email || "").trim().toLowerCase();
      return openDB().then(function (db) {
        return reqToPromise(store(db, STORE_USERS, "readwrite").delete(email)).then(function () {
          return clearSession(db).then(function () { notifyAuthChange(null); });
        });
      });
    },

    /** Subscribe to sign-in/sign-out/profile-update events. Returns an unsubscribe fn. */
    onAuthChange: function (fn) {
      authChangeListeners.push(fn);
      return function unsubscribe() {
        var i = authChangeListeners.indexOf(fn);
        if (i > -1) authChangeListeners.splice(i, 1);
      };
    },

    /** Resolves to "light" or "dark" if a theme has ever been saved, else null. */
    getTheme: function () {
      return openDB().then(function (db) {
        return reqToPromise(store(db, STORE_SETTINGS, "readonly").get(THEME_ID)).then(function (rec) {
          return rec ? rec.value : null;
        });
      });
    },

    /** Persist "light" or "dark" so every page (and future tabs) picks it up. */
    setTheme: function (theme) {
      theme = theme === "dark" ? "dark" : "light";
      return openDB().then(function (db) {
        return reqToPromise(store(db, STORE_SETTINGS, "readwrite").put({ id: THEME_ID, value: theme })).then(function () {
          notifyThemeChange(theme);
          if (themeChannel) themeChannel.postMessage(theme);
          return theme;
        });
      });
    },

    /** Subscribe to theme changes made elsewhere (e.g. another open tab). Returns an unsubscribe fn. */
    onThemeChange: function (fn) {
      themeChangeListeners.push(fn);
      return function unsubscribe() {
        var i = themeChangeListeners.indexOf(fn);
        if (i > -1) themeChangeListeners.splice(i, 1);
      };
    },

    /** The list of selectable accent colors, each with the psychological
     *  effect it was chosen for — useful for rendering a picker UI. */
    ACCENTS: ACCENTS,

    /** Resolves to the saved accent id, or the default ("emerald") if none was ever saved. */
    getAccent: function () {
      return openDB().then(function (db) {
        return reqToPromise(store(db, STORE_SETTINGS, "readonly").get(ACCENT_ID)).then(function (rec) {
          return rec ? rec.value : DEFAULT_ACCENT;
        });
      });
    },

    /** Persist the chosen accent id so every page (and future tabs) picks it up. */
    setAccent: function (accent) {
      var valid = ACCENTS.some(function (a) { return a.id === accent; });
      accent = valid ? accent : DEFAULT_ACCENT;
      return openDB().then(function (db) {
        return reqToPromise(store(db, STORE_SETTINGS, "readwrite").put({ id: ACCENT_ID, value: accent })).then(function () {
          notifyAccentChange(accent);
          if (accentChannel) accentChannel.postMessage(accent);
          return accent;
        });
      });
    },

    /** Subscribe to accent changes made elsewhere (e.g. another open tab). Returns an unsubscribe fn. */
    onAccentChange: function (fn) {
      accentChangeListeners.push(fn);
      return function unsubscribe() {
        var i = accentChangeListeners.indexOf(fn);
        if (i > -1) accentChangeListeners.splice(i, 1);
      };
    },

    /**
     * Applies the saved accent (or the default) to <body> as soon as
     * possible, without needing any picker UI — call this on every page
     * (including ones with no picker, like the logout screen) so the
     * chosen accent is consistent everywhere.
     */
    applySavedAccent: function () {
      return MitraAuth.getAccent().then(function (accent) {
        document.body.setAttribute("data-accent", accent);
        return accent;
      });
    },

    /**
     * One-call setup for the standard accent-color popover used across
     * Mitra's pages. Expects a trigger button, a panel to toggle, and a
     * container to render swatch buttons into.
     *
     * ids: { trigger, panel, swatches } — element ids, all optional
     * (defaults match the ids used across Mitra's pages).
     */
    initAccentPicker: function (ids) {
      ids = ids || {};
      var trigger = document.getElementById(ids.trigger || "accentBtn");
      var panel = document.getElementById(ids.panel || "accentPanel");
      var swatchWrap = document.getElementById(ids.swatches || "accentSwatches");

      if (swatchWrap && !swatchWrap.dataset.built) {
        swatchWrap.dataset.built = "true";
        swatchWrap.innerHTML = ACCENTS.map(function (a) {
          return '<button type="button" class="accent-swatch" data-accent-id="' + a.id + '" ' +
            'style="--swatch:' + a.swatch + ';" aria-pressed="false" title="' + a.name + ' — ' + a.effect + '">' +
            '<span class="accent-swatch-dot" aria-hidden="true"></span>' +
            '<span class="accent-swatch-label">' + a.name + '<small>' + a.effect + '</small></span>' +
            '</button>';
        }).join("");
      }

      function markActive(accent) {
        if (!swatchWrap) return;
        swatchWrap.querySelectorAll(".accent-swatch").forEach(function (btn) {
          var on = btn.getAttribute("data-accent-id") === accent;
          btn.setAttribute("aria-pressed", String(on));
        });
      }

      function apply(accent) {
        document.body.setAttribute("data-accent", accent);
        markActive(accent);
      }

      MitraAuth.getAccent().then(apply);

      if (swatchWrap) {
        swatchWrap.addEventListener("click", function (e) {
          var btn = e.target.closest(".accent-swatch");
          if (!btn) return;
          var accent = btn.getAttribute("data-accent-id");
          apply(accent);
          MitraAuth.setAccent(accent);
        });
      }

      if (trigger && panel) {
        trigger.addEventListener("click", function () {
          var open = panel.classList.toggle("open");
          trigger.setAttribute("aria-expanded", String(open));
        });
        document.addEventListener("click", function (e) {
          if (!panel.classList.contains("open")) return;
          if (panel.contains(e.target) || trigger.contains(e.target)) return;
          panel.classList.remove("open");
          trigger.setAttribute("aria-expanded", "false");
        });
        document.addEventListener("keydown", function (e) {
          if (e.key === "Escape" && panel.classList.contains("open")) {
            panel.classList.remove("open");
            trigger.setAttribute("aria-expanded", "false");
            trigger.focus();
          }
        });
      }

      MitraAuth.onAccentChange(function (accent) { apply(accent); });
    },

    /**
     * One-call setup for the standard sun/moon toggle button used on every
     * Mitra page. Applies the saved theme (falling back to the OS setting
     * the very first time, before anything has been saved), wires up the
     * click handler to flip + persist it, and keeps everything in sync if
     * the theme is changed from another open tab.
     *
     * ids: { toggle, sun, moon } — element ids, all optional
     * (defaults match the ids used across Mitra's pages).
     */
    initThemeToggle: function (ids) {
      ids = ids || {};
      var toggleBtn = document.getElementById(ids.toggle || "themeToggle");
      var sunIcon = document.getElementById(ids.sun || "themeIconSun");
      var moonIcon = document.getElementById(ids.moon || "themeIconMoon");
      var prefersDark = global.matchMedia && global.matchMedia("(prefers-color-scheme: dark)").matches;

      function apply(theme) {
        document.body.setAttribute("data-theme", theme);
        var dark = theme === "dark";
        if (sunIcon) sunIcon.style.display = dark ? "none" : "block";
        if (moonIcon) moonIcon.style.display = dark ? "block" : "none";
        if (toggleBtn) {
          toggleBtn.setAttribute("aria-pressed", String(dark));
          toggleBtn.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
        }
      }

      MitraAuth.getTheme().then(function (saved) {
        apply(saved || (prefersDark ? "dark" : "light"));
      });

      if (toggleBtn) {
        toggleBtn.addEventListener("click", function () {
          var next = document.body.getAttribute("data-theme") === "dark" ? "light" : "dark";
          apply(next);
          MitraAuth.setTheme(next);
        });
      }

      MitraAuth.onThemeChange(function (theme) { apply(theme); });
    }
  };

  global.MitraAuth = MitraAuth;
})(window);