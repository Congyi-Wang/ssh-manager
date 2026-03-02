const TotpModal = {
    _resolve: null,
    _reject: null,

    init() {
        const modal = document.getElementById('totp-modal');
        const input = document.getElementById('totp-input');
        const confirmBtn = document.getElementById('totp-confirm');
        const cancelBtn = document.getElementById('totp-cancel');
        const backdrop = modal.querySelector('.modal-backdrop');
        const errorEl = document.getElementById('totp-error');

        const submit = () => {
            const code = input.value.trim();
            if (code.length !== 6 || !/^\d{6}$/.test(code)) {
                errorEl.textContent = 'Enter a 6-digit code';
                errorEl.classList.remove('hidden');
                return;
            }
            errorEl.classList.add('hidden');
            modal.classList.add('hidden');
            if (this._resolve) this._resolve(code);
        };

        const cancel = () => {
            modal.classList.add('hidden');
            input.value = '';
            errorEl.classList.add('hidden');
            if (this._reject) this._reject(new Error('cancelled'));
        };

        confirmBtn.addEventListener('click', submit);
        cancelBtn.addEventListener('click', cancel);
        backdrop.addEventListener('click', cancel);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') submit();
            if (e.key === 'Escape') cancel();
        });
    },

    prompt(title) {
        return new Promise((resolve, reject) => {
            this._resolve = resolve;
            this._reject = reject;
            const modal = document.getElementById('totp-modal');
            const input = document.getElementById('totp-input');
            const errorEl = document.getElementById('totp-error');

            if (title) {
                document.getElementById('totp-modal-title').textContent = title;
            }
            input.value = '';
            errorEl.classList.add('hidden');
            modal.classList.remove('hidden');
            setTimeout(() => input.focus(), 100);
        });
    },
};
