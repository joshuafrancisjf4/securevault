/**
 * SecureVault 2.0 - Core Frontend Security & Interactive HUD Engine
 * Handles Smart Vault Lock, AES-256 unlock animations, client-side cryptographic password generator,
 * activity tracking, and UI reactivity.
 */

(function () {
    'use strict';

    // Global Toast Notification Helper
    window.showToast = function (message, type = 'info', duration = 3500) {
        let container = document.getElementById('cyberToastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'cyberToastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `cyber-toast toast-${type}`;

        let icon = '🛡️';
        if (type === 'success') icon = '✅';
        if (type === 'error') icon = '⚠️';
        if (type === 'lock') icon = '🔒';

        toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            toast.style.transition = '0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    };

    // =========================================================================
    // FEATURE 5: SMART PASSWORD GENERATOR (Client-Side Cryptographic RNG)
    // =========================================================================
    window.CyberGenerator = {
        state: {
            length: 16,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            masked: true,
            currentPassword: ''
        },

        init: function () {
            const modal = document.getElementById('passwordGenModal');
            if (!modal) return;

            const slider = document.getElementById('genLengthSlider');
            const lengthDisplay = document.getElementById('genLengthDisplay');
            const upperCheck = document.getElementById('genUpper');
            const lowerCheck = document.getElementById('genLower');
            const digitsCheck = document.getElementById('genDigits');
            const symbolsCheck = document.getElementById('genSymbols');
            const regenBtn = document.getElementById('genRegenBtn');
            const copyBtn = document.getElementById('genCopyBtn');
            const toggleMaskBtn = document.getElementById('genToggleMaskBtn');
            const useBtn = document.getElementById('genUsePasswordBtn');

            if (slider) {
                slider.addEventListener('input', (e) => {
                    this.state.length = parseInt(e.target.value, 10);
                    if (lengthDisplay) lengthDisplay.textContent = this.state.length;
                    this.generate();
                });
            }

            [upperCheck, lowerCheck, digitsCheck, symbolsCheck].forEach(el => {
                if (el) {
                    el.addEventListener('change', () => {
                        this.state.upper = upperCheck.checked;
                        this.state.lower = lowerCheck.checked;
                        this.state.digits = digitsCheck.checked;
                        this.state.symbols = symbolsCheck.checked;
                        this.generate();
                    });
                }
            });

            if (regenBtn) regenBtn.addEventListener('click', () => this.generate());
            if (copyBtn) copyBtn.addEventListener('click', () => this.copyToClipboard());
            if (toggleMaskBtn) toggleMaskBtn.addEventListener('click', () => this.toggleMask());
            if (useBtn) useBtn.addEventListener('click', () => this.usePasswordInForm());

            this.generate();
        },

        generate: function () {
            const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
            const digitChars = '0123456789';
            const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

            let pool = '';
            const required = [];

            if (this.state.upper) {
                pool += upperChars;
                required.push(this.getRandomChar(upperChars));
            }
            if (this.state.lower) {
                pool += lowerChars;
                required.push(this.getRandomChar(lowerChars));
            }
            if (this.state.digits) {
                pool += digitChars;
                required.push(this.getRandomChar(digitChars));
            }
            if (this.state.symbols) {
                pool += symbolChars;
                required.push(this.getRandomChar(symbolChars));
            }

            if (!pool) {
                pool = lowerChars + digitChars;
                required.push(this.getRandomChar(pool));
            }

            const remainingLen = Math.max(0, this.state.length - required.length);
            const randomArray = new Uint32Array(remainingLen);
            window.crypto.getRandomValues(randomArray);

            const rest = [];
            for (let i = 0; i < remainingLen; i++) {
                rest.push(pool[randomArray[i] % pool.length]);
            }

            // Cryptographically secure shuffle (Fisher-Yates)
            const combined = required.concat(rest);
            const shuffleArray = new Uint32Array(combined.length);
            window.crypto.getRandomValues(shuffleArray);

            for (let i = combined.length - 1; i > 0; i--) {
                const j = shuffleArray[i] % (i + 1);
                const temp = combined[i];
                combined[i] = combined[j];
                combined[j] = temp;
            }

            this.state.currentPassword = combined.join('');
            this.render();
        },

        getRandomChar: function (str) {
            const arr = new Uint32Array(1);
            window.crypto.getRandomValues(arr);
            return str[arr[0] % str.length];
        },

        toggleMask: function () {
            this.state.masked = !this.state.masked;
            this.render();
        },

        render: function () {
            const display = document.getElementById('genDisplay');
            const maskBtn = document.getElementById('genToggleMaskBtn');
            if (display) {
                display.textContent = this.state.masked
                    ? '•'.repeat(this.state.currentPassword.length)
                    : this.state.currentPassword;
            }
            if (maskBtn) {
                maskBtn.textContent = this.state.masked ? '👁️' : '🔒';
            }
            this.updateStrength(this.state.currentPassword);
        },

        updateStrength: function (password) {
            const meterFill = document.getElementById('genStrengthFill');
            const meterLabel = document.getElementById('genStrengthLabel');
            const entropyLabel = document.getElementById('genEntropyLabel');

            let poolSize = 0;
            if (/[a-z]/.test(password)) poolSize += 26;
            if (/[A-Z]/.test(password)) poolSize += 26;
            if (/[0-9]/.test(password)) poolSize += 10;
            if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

            const entropy = password.length * (poolSize > 0 ? Math.log2(poolSize) : 0);

            let score = 1;
            let label = 'Weak';
            if (entropy >= 80) { score = 4; label = 'Cyber-Grade (Ultra)'; }
            else if (entropy >= 56) { score = 3; label = 'Strong'; }
            else if (entropy >= 36) { score = 2; label = 'Moderate'; }

            if (meterFill) {
                meterFill.className = `strength-bar-fill score-${score}`;
            }
            if (meterLabel) meterLabel.textContent = label;
            if (entropyLabel) entropyLabel.textContent = `${Math.round(entropy)} bits entropy`;
        },

        copyToClipboard: function () {
            if (!this.state.currentPassword) return;
            navigator.clipboard.writeText(this.state.currentPassword).then(() => {
                window.showToast('Secure password copied to clipboard!', 'success');
            }).catch(() => {
                // Fallback
                const input = document.createElement('input');
                input.value = this.state.currentPassword;
                document.body.appendChild(input);
                input.select();
                document.execCommand('copy');
                document.body.removeChild(input);
                window.showToast('Secure password copied to clipboard!', 'success');
            });
        },

        usePasswordInForm: function () {
            const pwdInput = document.querySelector('input[name="vault_password"]') ||
                             document.querySelector('input[name="password"]');
            const confirmInput = document.querySelector('input[name="confirm_password"]');

            if (pwdInput) {
                pwdInput.value = this.state.currentPassword;
                pwdInput.type = 'text'; // momentarily show to user
                pwdInput.dispatchEvent(new Event('input'));
            }
            if (confirmInput) {
                confirmInput.value = this.state.currentPassword;
                confirmInput.type = 'text';
                confirmInput.dispatchEvent(new Event('input'));
            }

            window.closePasswordModal();
            window.showToast('Generated password populated into form!', 'success');
        }
    };

    window.openPasswordModal = function () {
        const modal = document.getElementById('passwordGenModal');
        if (modal) {
            modal.classList.add('active');
            window.CyberGenerator.generate();
        }
    };

    window.closePasswordModal = function () {
        const modal = document.getElementById('passwordGenModal');
        if (modal) modal.classList.remove('active');
    };

    // Close modal on click outside
    document.addEventListener('click', function (e) {
        const modal = document.getElementById('passwordGenModal');
        if (modal && e.target === modal) {
            window.closePasswordModal();
        }
    });

    // =========================================================================
    // FEATURE 2: SMART VAULT LOCK (Inactivity & Tab Visibility Detection)
    // =========================================================================
    window.SmartVaultLock = {
        vaultId: null,
        timeoutSeconds: 300, // default 5 minutes
        remainingSeconds: 300,
        timerInterval: null,
        lastActivity: Date.now(),
        lockOnTabHide: true,

        init: function (vaultId, timeoutSec = 300) {
            this.vaultId = vaultId;
            this.timeoutSeconds = timeoutSec;
            this.remainingSeconds = timeoutSec;
            this.lastActivity = Date.now();

            this.attachActivityListeners();
            this.attachVisibilityListener();
            this.startCountdown();
        },

        resetTimer: function () {
            this.lastActivity = Date.now();
            this.remainingSeconds = this.timeoutSeconds;
            this.updateDisplay();
        },

        attachActivityListeners: function () {
            const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
            const throttledReset = this.throttle(() => this.resetTimer(), 2000);
            events.forEach(evt => window.addEventListener(evt, throttledReset, { passive: true }));
        },

        attachVisibilityListener: function () {
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'hidden' && this.lockOnTabHide && this.vaultId) {
                    console.log('[SmartLock] Tab hidden, engaging lockdown defense...');
                    this.executeLockout('Tab hidden: Vault automatically locked for security.');
                }
            });
        },

        startCountdown: function () {
            if (this.timerInterval) clearInterval(this.timerInterval);
            this.updateDisplay();

            this.timerInterval = setInterval(() => {
                const elapsedSinceActivity = Math.floor((Date.now() - this.lastActivity) / 1000);
                this.remainingSeconds = Math.max(0, this.timeoutSeconds - elapsedSinceActivity);

                this.updateDisplay();

                if (this.remainingSeconds <= 0) {
                    clearInterval(this.timerInterval);
                    this.executeLockout('Inactivity timeout reached: Vault automatically locked.');
                }
            }, 1000);
        },

        updateDisplay: function () {
            const displayEl = document.getElementById('smartLockCountdown');
            if (!displayEl) return;

            const mins = Math.floor(this.remainingSeconds / 60);
            const secs = this.remainingSeconds % 60;
            displayEl.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;

            const pulseEl = document.getElementById('smartLockPulse');
            if (pulseEl) {
                if (this.remainingSeconds <= 30) {
                    pulseEl.style.background = '#ef4444';
                    pulseEl.style.boxShadow = '0 0 10px #ef4444';
                } else if (this.remainingSeconds <= 60) {
                    pulseEl.style.background = '#f59e0b';
                    pulseEl.style.boxShadow = '0 0 10px #f59e0b';
                } else {
                    pulseEl.style.background = '#10b981';
                    pulseEl.style.boxShadow = '0 0 8px #10b981';
                }
            }
        },

        executeLockout: function (reason = 'Vault locked.') {
            if (!this.vaultId) return;

            // Immediately clear sensitive view from client DOM
            const sensitiveContainer = document.getElementById('vaultSensitiveContent');
            if (sensitiveContainer) {
                sensitiveContainer.innerHTML = `
                    <div style="text-align:center; padding: 40px 20px;">
                        <div style="font-size: 48px; margin-bottom: 15px;">🔒</div>
                        <h3 style="color: var(--cyan-primary);">Vault Locked</h3>
                        <p style="color: var(--text-muted);">${reason}</p>
                        <p style="margin-top: 15px;"><a href="/open_vault/${this.vaultId}" class="btn btn-sm">Enter Master Password</a></p>
                    </div>
                `;
            }

            // Call backend lock API to purge decrypted keys from session
            fetch(`/api/lock_vault/${this.vaultId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            }).then(() => {
                window.location.href = `/open_vault/${this.vaultId}`;
            }).catch(() => {
                window.location.href = `/open_vault/${this.vaultId}`;
            });
        },

        throttle: function (func, limit) {
            let inThrottle;
            return function () {
                const args = arguments;
                const context = this;
                if (!inThrottle) {
                    func.apply(context, args);
                    inThrottle = true;
                    setTimeout(() => inThrottle = false, limit);
                }
            };
        }
    };

    // =========================================================================
    // FEATURE 6: FUTURISTIC VAULT UNLOCK & LOCK ANIMATION CONTROLLER
    // =========================================================================
    window.VaultAnimationController = {
        hudEl: null,
        statusEl: null,

        init: function () {
            this.hudEl = document.getElementById('vaultAnimHud');
            this.statusEl = document.getElementById('vaultAnimStatus');
            const form = document.getElementById('vaultUnlockForm');

            if (form) {
                form.addEventListener('submit', (e) => this.handleUnlockSubmit(e));
            }

            const lockBtn = document.getElementById('manualLockBtn');
            if (lockBtn) {
                lockBtn.addEventListener('click', (e) => this.handleLockSubmit(e));
            }
        },

        setStatus: function (text) {
            if (this.statusEl) {
                this.statusEl.textContent = text;
            }
        },

        setState: function (state) {
            if (!this.hudEl) return;
            this.hudEl.className = `vault-animation-hud state-${state}`;
        },

        handleUnlockSubmit: async function (e) {
            e.preventDefault();
            const form = e.target;
            const vaultId = form.dataset.vaultId;
            const passwordInput = form.querySelector('input[name="vault_password"]');
            const submitBtn = form.querySelector('button[type="submit"]');
            const password = passwordInput ? passwordInput.value : '';

            if (!password) {
                this.setStatus('Please enter master password');
                return;
            }

            // Trigger Verification Animation
            this.setState('verifying');
            if (submitBtn) submitBtn.disabled = true;

            const iconEl = document.getElementById('vaultDoorLockIcon');
            if (iconEl) iconEl.textContent = '⚡';

            this.setStatus('Verifying credentials...');
            await this.sleep(400);

            this.setStatus('Deriving AES-256 keys via scrypt KDF...');
            await this.sleep(400);

            this.setStatus('Decrypting vault header & verifying auth tag...');

            try {
                const response = await fetch(`/api/vault_unlock/${vaultId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vault_password: password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    this.setState('unlocked');
                    if (iconEl) iconEl.textContent = '🔓';
                    this.setStatus('Authentication verified. Vault Unlocked!');
                    window.showToast('Vault unlocked successfully!', 'success');

                    await this.sleep(600);
                    // Seamless redirect to unlocked vault
                    window.location.href = `/open_vault/${vaultId}`;
                } else {
                    this.setState('denied');
                    if (iconEl) iconEl.textContent = '❌';
                    this.setStatus(data.error || 'Access Denied: Invalid Master Password');
                    window.showToast(data.error || 'Invalid Master Password', 'error');

                    if (submitBtn) submitBtn.disabled = false;
                    setTimeout(() => {
                        this.setState('locked');
                        if (iconEl) iconEl.textContent = '🔒';
                    }, 2200);
                }
            } catch (err) {
                console.error('Unlock error:', err);
                // Fallback to native form post
                form.submit();
            }
        },

        handleLockSubmit: async function (e) {
            e.preventDefault();
            const vaultId = e.currentTarget.dataset.vaultId;
            if (!vaultId) return;

            window.showToast('Securing vault & wiping cryptographic keys...', 'lock');

            try {
                await fetch(`/api/lock_vault/${vaultId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (err) {
                console.error('Lock error:', err);
            }
            window.location.href = `/open_vault/${vaultId}`;
        },

        sleep: function (ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
    };

    // Password strength meter for standard forms (signup / create vault)
    window.initPasswordStrengthMeter = function (inputId, fillId, labelId) {
        const input = document.getElementById(inputId);
        const fill = document.getElementById(fillId);
        const label = document.getElementById(labelId);
        if (!input || !fill) return;

        input.addEventListener('input', () => {
            const pwd = input.value;
            let pool = 0;
            if (/[a-z]/.test(pwd)) pool += 26;
            if (/[A-Z]/.test(pwd)) pool += 26;
            if (/[0-9]/.test(pwd)) pool += 10;
            if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;

            const entropy = pwd.length * (pool > 0 ? Math.log2(pool) : 0);
            let score = 0;
            let txt = 'Enter password';

            if (pwd.length > 0) {
                if (entropy < 36) { score = 1; txt = 'Weak (Needs symbols/length)'; }
                else if (entropy < 56) { score = 2; txt = 'Moderate'; }
                else if (entropy < 80) { score = 3; txt = 'Strong'; }
                else { score = 4; txt = 'Cyber-Grade (Maximum Protection)'; }
            }

            fill.className = `strength-bar-fill score-${score}`;
            if (label) label.textContent = txt;
        });
    };

    // Toggle password visibility helper
    window.togglePasswordVisibility = function (inputId, btn) {
        const input = document.getElementById(inputId);
        if (!input) return;
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '👁️';
        } else {
            input.type = 'password';
            btn.textContent = '🔒';
        }
    };

    // Initialize components on DOM ready
    document.addEventListener('DOMContentLoaded', function () {
        window.CyberGenerator.init();
        window.VaultAnimationController.init();
    });

})();
