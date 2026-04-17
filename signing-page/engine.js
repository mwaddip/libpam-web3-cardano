/**
 * Signing page engine — Cardano CIP-30 authentication.
 *
 * Self-initializes on DOMContentLoaded. Reads configuration from the global
 * CONFIG object (injected by the generator). Finds required DOM elements by
 * ID per the page template interface contract.
 *
 * Required DOM element IDs:
 *   btn-connect, btn-sign, wallet-address, status-message,
 *   step-connect, step-sign
 *
 * Extra (template-allowed) IDs used:
 *   wallet-list — populated with per-wallet buttons after btn-connect click
 *   code, machine — readonly display of OTP / machine_id from session
 *
 * CSS classes toggled by this bundle:
 *   hidden, active, completed, disabled, loading, error, success
 */
(function () {
  'use strict';

  // ── Helpers ──────────────────────────────────────────────────────────

  function $(id) { return document.getElementById(id); }

  // ── Status management ───────────────────────────────────────────────

  function setStatus(msg, type) {
    var el = $('status-message');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden', 'error', 'success');
    if (type) el.classList.add(type);
    if (!msg) el.classList.add('hidden');
  }

  function clearStatus() {
    var el = $('status-message');
    if (!el) return;
    el.textContent = '';
    el.classList.add('hidden');
    el.classList.remove('error', 'success');
  }

  // ── Step state management ───────────────────────────────────────────

  function activateStep(stepId) {
    var el = $(stepId);
    if (!el) return;
    el.classList.remove('hidden', 'completed');
    el.classList.add('active');
  }

  function completeStep(stepId) {
    var el = $(stepId);
    if (!el) return;
    el.classList.remove('active', 'hidden');
    el.classList.add('completed');
  }

  // ── Button state ────────────────────────────────────────────────────

  function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.classList.add('loading', 'disabled');
      btn.disabled = true;
    } else {
      btn.classList.remove('loading', 'disabled');
      btn.disabled = false;
    }
  }

  // ── Wallet detection (CIP-30) ───────────────────────────────────────

  var KNOWN_WALLETS = ['eternl', 'nami', 'lace', 'flint', 'typhon', 'yoroi', 'gerowallet', 'nufi'];

  function detectWallets() {
    var cardano = window.cardano;
    if (!cardano) return [];

    var found = [];
    var seen = {};

    for (var i = 0; i < KNOWN_WALLETS.length; i++) {
      var name = KNOWN_WALLETS[i];
      if (cardano[name] && typeof cardano[name].enable === 'function') {
        found.push({ key: name, label: cardano[name].name || name });
        seen[name] = true;
      }
    }

    var keys = Object.keys(cardano);
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (!seen[k] && cardano[k] && typeof cardano[k].enable === 'function') {
        found.push({ key: k, label: cardano[k].name || k });
      }
    }

    return found;
  }

  // ── Main logic ──────────────────────────────────────────────────────

  function init() {
    var btnConnect = $('btn-connect');
    var btnSign = $('btn-sign');
    var walletAddress = $('wallet-address');
    var walletList = $('wallet-list');
    var codeEl = $('code');
    var machineEl = $('machine');

    var sessionId = (new URLSearchParams(window.location.search)).get('session');

    if (!sessionId) {
      setStatus('No session. Use the link from your terminal.', 'error');
      if (btnConnect) {
        btnConnect.disabled = true;
        btnConnect.classList.add('disabled');
      }
      return;
    }

    activateStep('step-connect');

    var api = null;          // CIP-30 API handle
    var usedAddress = '';    // bech32 Cardano address
    var otp = '';
    var machineId = '';

    function loadSession() {
      fetch('/auth/pending/' + sessionId).then(function (res) {
        if (!res.ok) { setStatus('Session not found or expired', 'error'); return; }
        return res.json();
      }).then(function (data) {
        if (!data) return;
        otp = data.otp || '';
        machineId = data.machine_id || '';
        if (codeEl) codeEl.value = otp;
        if (machineEl) machineEl.value = machineId;
      }).catch(function () {
        setStatus('Failed to load session', 'error');
      });
    }

    function showWalletPicker() {
      var wallets = detectWallets();
      if (wallets.length === 0) {
        setStatus('No CIP-30 wallets detected. Install Eternl, Nami, or Lace.', 'error');
        return;
      }

      while (walletList.firstChild) walletList.removeChild(walletList.firstChild);

      for (var i = 0; i < wallets.length; i++) {
        var w = wallets[i];
        var btn = document.createElement('button');
        btn.className = 'wallet-btn';
        btn.textContent = w.label;
        btn.dataset.wallet = w.key;
        btn.onclick = (function (key) {
          return function () { connectWallet(key); };
        })(w.key);
        walletList.appendChild(btn);
      }

      btnConnect.classList.add('hidden');
      walletList.classList.remove('hidden');
    }

    function connectWallet(name) {
      setStatus('Connecting to ' + name + '...', '');

      window.cardano[name].enable().then(function (a) {
        api = a;
        return api.getUsedAddresses();
      }).then(function (addresses) {
        if (addresses && addresses.length) {
          usedAddress = addresses[0];
          return null;
        }
        return api.getUnusedAddresses();
      }).then(function (unused) {
        if (unused && unused.length) usedAddress = unused[0];
        if (!usedAddress) throw new Error('No addresses in wallet');

        if (walletAddress) walletAddress.textContent = usedAddress;
        completeStep('step-connect');
        activateStep('step-sign');
        clearStatus();
        loadSession();
      }).catch(function (e) {
        setStatus('Connection failed: ' + (e.message || e), 'error');
      });
    }

    function sign() {
      if (!api) { setStatus('No wallet connected', 'error'); return; }
      if (!otp || !machineId) { setStatus('Session data incomplete', 'error'); return; }

      var msg = 'Authenticate to ' + machineId + ' with code: ' + otp;
      // CIP-30 signData: address (bech32), payload (hex-encoded UTF-8)
      var msgBytes = new TextEncoder().encode(msg);
      var msgHex = '';
      for (var i = 0; i < msgBytes.length; i++) {
        msgHex += ('0' + msgBytes[i].toString(16)).slice(-2);
      }

      setButtonLoading(btnSign, true);

      api.signData(usedAddress, msgHex).then(function (result) {
        // result = { signature: hex (COSE_Sign1), key: hex (COSE_Key) }
        var payload = JSON.stringify({
          signature: result.signature,
          key: result.key,
          otp: otp,
          machineId: machineId,
        });

        return fetch('/auth/callback/' + sessionId, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
        });
      }).then(function (cb) {
        if (cb.ok) {
          completeStep('step-sign');
          setStatus('Signature sent! Press Enter in your terminal.', 'success');
        } else {
          setStatus('Server rejected the signature (' + cb.status + ')', 'error');
        }
      }).catch(function (e) {
        setStatus('Signing failed: ' + (e.message || e), 'error');
      }).finally(function () {
        setButtonLoading(btnSign, false);
      });
    }

    if (btnConnect) btnConnect.onclick = showWalletPicker;
    if (btnSign) btnSign.onclick = sign;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
