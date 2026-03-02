const API = {
    _key: null,

    setKey(key) {
        this._key = key;
        localStorage.setItem('ssh_manager_api_key', key);
    },

    getKey() {
        if (!this._key) {
            this._key = localStorage.getItem('ssh_manager_api_key');
        }
        return this._key;
    },

    clearKey() {
        this._key = null;
        localStorage.removeItem('ssh_manager_api_key');
    },

    async request(method, path, body, extraHeaders) {
        const headers = {
            'Content-Type': 'application/json',
        };
        const key = this.getKey();
        if (key) {
            headers['X-API-Key'] = key;
        }
        if (extraHeaders) {
            Object.assign(headers, extraHeaders);
        }
        const opts = { method, headers };
        if (body && method !== 'GET') {
            opts.body = JSON.stringify(body);
        }
        const resp = await fetch(path, opts);
        const data = await resp.json();
        if (resp.status === 401) {
            API.clearKey();
            window.location.reload();
            throw new Error('Unauthorized');
        }
        if (!resp.ok) {
            const err = new Error(data.error || `HTTP ${resp.status}`);
            err.status = resp.status;
            err.data = data;
            throw err;
        }
        return data;
    },

    get(path) { return this.request('GET', path); },
    post(path, body, headers) { return this.request('POST', path, body, headers); },
    patch(path, body, headers) { return this.request('PATCH', path, body, headers); },
    delete(path, body, headers) { return this.request('DELETE', path, body, headers); },
};
