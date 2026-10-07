// app.js - Main application logic for Sísifo web UI
class SisifoApp {
    constructor() {
        this.csrfToken = document.getElementById('csrf-token')?.dataset.token || '';
        this.currentTab = 'overview';
        this.jobsPolling = new Map();
        this.init();
    }

    async init() {
        this.bindEvents();
        await this.loadOverview();
        this.startJobPolling();
    }

    bindEvents() {
        document.addEventListener('click', async (event) => {
            if (event.target.matches('.cancel-job')) {
                const id = event.target.closest('[data-job-id]').dataset.jobId;
                await this.api(`/api/jobs/${id}/cancel`, {method: 'POST'});
            }
        });
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
        });

        // Logout
        document.getElementById('logout-btn')?.addEventListener('click', () => this.logout());

        // Sessions
        document.getElementById('session-filter')?.addEventListener('input', () => this.filterSessions());
        document.getElementById('session-status-filter')?.addEventListener('change', () => this.filterSessions());

        // Reports
        document.getElementById('load-report-btn')?.addEventListener('click', () => this.loadReport());
        document.getElementById('download-md-btn')?.addEventListener('click', () => this.downloadReport('md'));
        document.getElementById('download-json-btn')?.addEventListener('click', () => this.downloadReport('json'));
        document.getElementById('verify-report-btn')?.addEventListener('click', () => this.verifyReport());
        document.getElementById('compare-btn')?.addEventListener('click', () => this.compareSessions());

        // Scan form
        document.getElementById('scan-form')?.addEventListener('submit', (e) => this.submitScan(e));

        // Analyze form
        document.getElementById('analyze-form')?.addEventListener('submit', (e) => this.submitAnalyze(e));
        document.getElementById('preview-analysis')?.addEventListener('click', () => this.previewAnalysis());
        document.getElementById('import-form')?.addEventListener('submit', (e) => this.importNmap(e));

        // Network
        document.getElementById('network-doctor-btn')?.addEventListener('click', () => this.loadNetworkDiagnostics());
        document.getElementById('network-import-form')?.addEventListener('submit', (e) => this.importNetworkCapture(e));
        document.getElementById('network-refresh-captures')?.addEventListener('click', () => this.loadNetworkCaptures());

        // OSINT
        document.getElementById('osint-query-form')?.addEventListener('submit', (e) => this.submitOsintQuery(e));

        // Config forms
        document.getElementById('config-ai-form')?.addEventListener('submit', (e) => this.saveAiConfig(e));
        document.getElementById('config-web-form')?.addEventListener('submit', (e) => this.saveWebPassword(e));

        // Load initial data
        this.loadModules();
        this.loadOsintConnectors();
        this.loadConfigStatus();
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`tab-${tabName}`)?.classList.add('active');
        document.querySelector(`.tab-btn[data-tab="${tabName}"]`)?.classList.add('active');
        this.currentTab = tabName;

        if (tabName === 'sessions') this.loadSessions();
        else if (tabName === 'reports') this.loadReportSessionIds();
        else if (tabName === 'network') this.loadNetworkCaptures();
        else if (tabName === 'osint') this.loadOsintConnectors();
        else if (tabName === 'config') this.loadConfigStatus();
    }

    async api(path, options = {}) {
        const defaults = {
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.csrfToken
            }
        };
        const response = await fetch(path, { ...defaults, ...options });
        if (response.status === 401) {
            window.location.href = '/login';
            throw new Error('Sessão expirada');
        }
        if (!response.ok) {
            const data = await response.json().catch(() => ({ detail: response.statusText }));
            throw new Error(data.detail || `HTTP ${response.status}`);
        }
        return response.json();
    }

    async loadOverview() {
        try {
            const [sessions, modules, config] = await Promise.all([
                this.api('/api/sessions'),
                this.api('/api/modules'),
                this.api('/api/config/status')
            ]);

            this.renderOverviewSessions(sessions.sessions.slice(0, 5));
            this.renderOverviewTools(modules.modules);
            this.renderOverviewIntegrations(config);
        } catch (err) {
            console.error('Failed to load overview:', err);
        }
    }

    renderOverviewSessions(sessions) {
        const container = document.getElementById('overview-sessions');
        if (!sessions.length) {
            container.innerHTML = '<p class="empty">Nenhuma sessão encontrada</p>';
            return;
        }
        container.innerHTML = sessions.map(s => `
            <div class="list-item">
                <div>
                    <div class="label">${this.escapeHtml(s.id)}</div>
                    <div class="value">${this.escapeHtml(s.project)} / ${this.escapeHtml(s.target)}</div>
                </div>
                <span class="status status-${s.status}">${s.status}</span>
            </div>
        `).join('');
    }

    renderOverviewTools(modules) {
        const container = document.getElementById('overview-tools');
        container.innerHTML = modules.map(m => `
            <div class="list-item">
                <div class="label">${this.escapeHtml(m.name)}</div>
                <div class="value">${m.experimental ? '<span class="status status-pending">Experimental</span>' : '<span class="status status-completed">Disponível</span>'}</div>
            </div>
        `).join('');
    }

    renderOverviewIntegrations(config) {
        const container = document.getElementById('overview-integrations');
        const ai = config.ai;
        const osint = config.osint;
        container.innerHTML = `
            <div class="list-item">
                <div class="label">IA (${ai.provider || 'não configurado'})</div>
                <div class="value">${ai.configured ? '<span class="status status-completed">Configurado</span>' : '<span class="status status-pending">Não configurado</span>'}</div>
            </div>
            ${Object.entries(osint).map(([id, configured]) => `
                <div class="list-item">
                    <div class="label">${id}</div>
                    <div class="value">${configured ? '<span class="status status-completed">Configurado</span>' : '<span class="status status-pending">Não configurado</span>'}</div>
                </div>
            `).join('') || '<p class="empty">Nenhum conector OSINT</p>'}
        `;
    }

    async loadSessions() {
        try {
            const data = await this.api('/api/sessions');
            this.allSessions = data.sessions;
            this.renderSessionsTable(data.sessions);
        } catch (err) {
            this.showToast('Erro ao carregar sessões: ' + err.message, 'error');
        }
    }

    renderSessionsTable(sessions) {
        const tbody = document.querySelector('#sessions-table tbody');
        tbody.innerHTML = sessions.map(s => `
            <tr data-id="${this.escapeHtml(s.id)}">
                <td><code>${this.escapeHtml(s.id)}</code></td>
                <td>${this.escapeHtml(s.project)}</td>
                <td>${this.escapeHtml(s.target)}</td>
                <td><span class="status status-${s.status}">${s.status}</span></td>
                <td>${s.tools.join(', ') || '-'}</td>
                <td>${this.formatDate(s.created_at)}</td>
                <td>
                    <div class="actions">
                        <button class="btn btn-secondary btn-small" onclick="app.showSessionDetail('${this.escapeHtml(s.id)}')">Detalhes</button>
                        <button class="btn btn-secondary btn-small" onclick="app.loadReportForSession('${this.escapeHtml(s.id)}')">Relatório</button>
                    </div>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('tr').forEach(tr => {
            tr.addEventListener('click', (e) => {
                if (!e.target.closest('button')) {
                    this.showSessionDetail(tr.dataset.id);
                }
            });
        });
    }

    filterSessions() {
        const filter = document.getElementById('session-filter')?.value.toLowerCase() || '';
        const statusFilter = document.getElementById('session-status-filter')?.value || '';
        const filtered = this.allSessions.filter(s => {
            const matchesFilter = s.id.toLowerCase().includes(filter) ||
                s.project.toLowerCase().includes(filter) ||
                s.target.toLowerCase().includes(filter);
            const matchesStatus = !statusFilter || s.status === statusFilter;
            return matchesFilter && matchesStatus;
        });
        this.renderSessionsTable(filtered);
    }

    async showSessionDetail(sessionId) {
        try {
            const data = await this.api(`/api/sessions/${sessionId}`);
            const panel = document.getElementById('session-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Detalhes da Sessão: ${this.escapeHtml(data.id)}</h3>
                <div class="grid grid-2">
                    <div>
                        <p><strong>Projeto:</strong> ${this.escapeHtml(data.project)}</p>
                        <p><strong>Alvo:</strong> ${this.escapeHtml(data.target)}</p>
                        <p><strong>Status:</strong> <span class="status status-${data.status}">${data.status}</span></p>
                        <p><strong>Criada em:</strong> ${this.formatDate(data.created_at)}</p>
                    </div>
                    <div>
                        <p><strong>Ferramentas:</strong> ${data.runs.map(r => r.tool).join(', ') || 'Nenhuma'}</p>
                    </div>
                </div>
                <h4>Execuções</h4>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Ferramenta</th><th>Status</th><th>Início</th><th>Fim</th><th>Erro</th><th>Imagem</th></tr></thead>
                        <tbody>
                            ${data.runs.map(r => `
                                <tr>
                                    <td>${this.escapeHtml(r.tool)}</td>
                                    <td><span class="status status-${r.status}">${r.status}</span></td>
                                    <td>${r.started_at ? this.formatDate(r.started_at) : '-'}</td>
                                    <td>${r.finished_at ? this.formatDate(r.finished_at) : '-'}</td>
                                    <td>${r.error ? `<span class="job-error">${this.escapeHtml(r.error)}</span>` : '-'}</td>
                                    <td><code>${this.escapeHtml(r.image_id || '-')}</code></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (err) {
            this.showToast('Erro ao carregar detalhes: ' + err.message, 'error');
        }
    }

    async loadReport() {
        const sessionId = document.getElementById('report-session-input')?.value.trim();
        if (!sessionId) {
            this.showToast('Informe o ID da sessão', 'warning');
            return;
        }
        await this.loadReportForSession(sessionId);
    }

    async loadReportForSession(sessionId) {
        try {
            this.currentReportSession = sessionId;
            const [md, json] = await Promise.all([
                this.api(`/api/reports/${session_id}?format=md`),
                this.api(`/api/reports/${session_id}?format=json`)
            ]);
            this.currentReportMd = md;
            this.currentReportJson = json;
            document.getElementById('report-content')?.classList.remove('hidden');
            document.getElementById('report-viewer').textContent = md;
            document.getElementById('report-session-input').value = sessionId;
            this.showToast('Relatório carregado', 'success');
        } catch (err) {
            this.showToast('Erro ao carregar relatório: ' + err.message, 'error');
        }
    }

    downloadReport(format) {
        if (!this.currentReportSession) return;
        window.location.href = `/api/download/${this.currentReportSession}/${format === 'md' ? 'report-md' : 'report-json'}`;
    }

    async verifyReport() {
        if (!this.currentReportSession) return;
        try {
            const result = await this.api(`/api/sessions/verify/${this.currentReportSession}`, { method: 'POST' });
            this.showToast(`Integridade verificada: ${result.count} evidências`, 'success');
        } catch (err) {
            this.showToast('Erro na verificação: ' + err.message, 'error');
        }
    }

    async compareSessions() {
        const before = document.getElementById('compare-before')?.value.trim();
        const after = document.getElementById('compare-after')?.value.trim();
        if (!before || !after) {
            this.showToast('Informe ambas as sessões', 'warning');
            return;
        }
        try {
            const result = await this.api('/api/sessions/compare', {
                method: 'POST',
                body: JSON.stringify({ before, after })
            });
            document.getElementById('compare-result').classList.remove('hidden');
            document.getElementById('compare-result').textContent = JSON.stringify(result, null, 2);
            this.showToast('Comparação concluída', 'success');
        } catch (err) {
            this.showToast('Erro na comparação: ' + err.message, 'error');
        }
    }

    async loadModules() {
        try {
            const data = await this.api('/api/modules');
            const select = document.getElementById('scan-modules');
            select.innerHTML = data.modules.map(m => `
                <option value="${m.name}">${m.name}${m.experimental ? ' (experimental)' : ''}</option>
            `).join('');
        } catch (err) {
            console.error('Failed to load modules:', err);
        }
    }

    async submitScan(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        const modules = Array.from(formData.getAll('modules')).join(',') || 'nmap';

        if (!window.confirm('Executar ferramentas neste alvo autorizado?')) return;
        try {
            const result = await this.api('/api/scan', {
                method: 'POST',
                body: JSON.stringify({
                    target: formData.get('target'),
                    modules,
                    project: formData.get('project'),
                    timeout: parseInt(formData.get('timeout'))
                })
            });
            this.showToast('Execução iniciada', 'success');
            this.trackJob(result.job_id, 'scan');
            form.reset();
        } catch (err) {
            this.showToast('Erro ao iniciar execução: ' + err.message, 'error');
        }
    }

    async previewAnalysis() {
        try {
            const result = await this.api('/api/analyze/preview', {
                method: 'POST',
                body: JSON.stringify({session_id: document.getElementById('analyze-session').value})
            });
            const preview = document.getElementById('analysis-preview');
            preview.textContent = JSON.stringify(result, null, 2);
            preview.classList.remove('hidden');
        } catch (error) {
            this.showToast('Erro na prévia: ' + error.message, 'error');
        }
    }

    async importNmap(e) {
        e.preventDefault();
        const button = e.target.querySelector('button[type="submit"]');
        button.disabled = true;
        try {
            const result = await this.api('/api/import-nmap', {
                method: 'POST',
                headers: {'X-CSRF-Token': this.csrfToken},
                body: new FormData(e.target)
            });
            this.showToast('Sessão importada: ' + result.session_id, 'success');
            document.getElementById('analyze-session').value = result.session_id;
            document.getElementById('report-session-input').value = result.session_id;
        } catch (error) {
            this.showToast('Erro na importação: ' + error.message, 'error');
        } finally {
            button.disabled = false;
        }
    }

    async submitAnalyze(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);

        if (!window.confirm('Revisou os dados? A analise pode enviar evidencias ao provedor configurado. Export nao envia dados.')) return;
        try {
            const result = await this.api('/api/analyze', {
                method: 'POST',
                body: JSON.stringify({
                    session_id: formData.get('session_id'),
                    provider: formData.get('provider') || undefined,
                    model: formData.get('model') || undefined,
                    endpoint: formData.get('endpoint') || undefined,
                    max_batches: parseInt(formData.get('max_batches')),
                    max_seconds: parseInt(formData.get('max_seconds')),
                    token_budget: parseInt(formData.get('token_budget')),
                    resume_id: formData.get('resume_id') || undefined
                })
            });
            this.showToast('Análise iniciada', 'success');
            this.trackJob(result.job_id, 'analyze');
        } catch (err) {
            this.showToast('Erro ao iniciar análise: ' + err.message, 'error');
        }
    }

    async loadOsintConnectors() {
        try {
            const data = await this.api('/api/osint/connectors');
            const select = document.getElementById('osint-connector');
            select.innerHTML = Object.entries(data.connectors).map(([id, meta]) => `
                <option value="${this.escapeHtml(id)}" ${!meta.configured || meta.status === 'planned' ? 'disabled' : ''}>
                    ${this.escapeHtml(meta.name)} (${meta.configured ? 'configurado' : 'configure na aba Configurações'}; ${this.escapeHtml(meta.status)})
                </option>
            `).join('');

            const container = document.getElementById('osint-connectors');
            container.innerHTML = Object.entries(data.connectors).map(([id, meta]) => `
                <div class="osint-connector">
                    <h4>${this.escapeHtml(meta.name)} <span class="status status-${meta.status}">${meta.status}</span></h4>
                    <div class="meta">
                        ${this.escapeHtml(meta.description)}<br>
                        Configuração: ${meta.configured ? 'pronta' : 'necessária na aba Configurações'}<br>
                        Tipos: ${this.escapeHtml(meta.query_types.join(', '))}<br>
                        Limites: ${this.escapeHtml(JSON.stringify(meta.limits))}
                    </div>
                </div>
            `).join('');
        } catch (err) {
            console.error('Failed to load OSINT connectors:', err);
        }
    }

    async submitOsintQuery(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);

        if (!window.confirm('Autorizar esta consulta ao conector selecionado?')) return;
        try {
            const result = await this.api('/api/osint/query', {
                method: 'POST',
                body: JSON.stringify({
                    connector_id: formData.get('connector_id'),
                    query: formData.get('query'),
                    query_type: formData.get('query_type')
                })
            });
            this.showToast('Consulta OSINT iniciada', 'success');
            this.trackJob(result.job_id, 'osint');
        } catch (err) {
            this.showToast('Erro na consulta OSINT: ' + err.message, 'error');
        }
    }

    async loadConfigStatus() {
        try {
            const config = await this.api('/api/config/status');
            document.getElementById('config-provider').value = config.ai.provider || 'nvidia';
            document.getElementById('config-model').value = config.ai.model || '';

            const container = document.getElementById('osint-credentials');
            container.innerHTML = Object.entries(config.osint).map(([id, configured]) => `
                <div class="osint-connector">
                    <h4>${id} <span class="status status-${configured ? 'completed' : 'pending'}">${configured ? 'Configurado' : 'Não configurado'}</span></h4>
                    <button class="btn btn-secondary btn-small" onclick="app.configureOsintConnector('${id}')">
                        ${configured ? 'Reconfigurar' : 'Configurar'}
                    </button>
                </div>
            `).join('');
        } catch (err) {
            console.error('Failed to load config status:', err);
        }
    }

    async saveAiConfig(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);

        try {
            await this.api('/api/config/ai', {method: 'POST', body: JSON.stringify({
                provider: formData.get('provider'), model: formData.get('model'),
                nvidia_key: formData.get('nvidia_key') || null
            })});
            form.querySelector('[name=nvidia_key]').value = '';
            this.showToast('Configuracao salva', 'success');
            await this.loadConfigStatus();
        } catch (err) { this.showToast(err.message, 'error'); }
    }

    async saveWebPassword(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        const pwd = formData.get('web_password');
        const confirm = formData.get('web_password_confirm');

        if (pwd !== confirm) {
            this.showToast('Senhas não conferem', 'error');
            return;
        }

        try {
            await this.api('/api/config/web', {method: 'POST', body: JSON.stringify({password: pwd})});
            form.reset();
            window.location.href = '/login';
        } catch (err) { this.showToast(err.message, 'error'); }
    }

    async loadNetworkDiagnostics() {
        const btn = document.getElementById('network-doctor-btn');
        btn.disabled = true;
        btn.textContent = 'Verificando...';
        try {
            const data = await this.api('/api/network/diagnostics');
            const pre = document.getElementById('network-diagnostics');
            pre.textContent = JSON.stringify(data, null, 2);
            pre.classList.remove('hidden');
            this.showToast('Diagnóstico concluído', 'success');
        } catch (err) {
            this.showToast('Erro no diagnóstico: ' + err.message, 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Verificar';
        }
    }

    async loadNetworkCaptures() {
        try {
            const data = await this.api('/api/network/captures');
            const tbody = document.querySelector('#network-captures-table tbody');
            tbody.innerHTML = data.captures.map(c => `
                <tr data-id="${this.escapeHtml(c.id)}">
                    <td><code>${this.escapeHtml(c.id.slice(0, 16))}...</code></td>
                    <td>${this.escapeHtml(c.source)}</td>
                    <td><span class="status status-${c.status}">${c.status}</span></td>
                    <td>${this.escapeHtml(c.interface_name || c.interface_id || '-')}</td>
                    <td>${c.packet_count.toLocaleString()}</td>
                    <td>${c.file_size.toLocaleString()} bytes</td>
                    <td>${this.formatDate(c.created_at)}</td>
                    <td>
                        <div class="actions">
                            <button class="btn btn-secondary btn-small" onclick="app.showNetworkCaptureDetail('${this.escapeHtml(c.id)}')">Detalhes</button>
                            <button class="btn btn-secondary btn-small" onclick="app.loadNetworkPackets('${this.escapeHtml(c.id)}')">Pacotes</button>
                            <button class="btn btn-secondary btn-small" onclick="app.loadNetworkStats('${this.escapeHtml(c.id)}')">Estatísticas</button>
                            <button class="btn btn-secondary btn-small" onclick="app.loadNetworkReport('${this.escapeHtml(c.id)}')">Relatório</button>
                        </div>
                    </td>
                </tr>
            `).join('');
            tbody.querySelectorAll('tr').forEach(tr => {
                tr.addEventListener('click', (e) => {
                    if (!e.target.closest('button')) {
                        this.showNetworkCaptureDetail(tr.dataset.id);
                    }
                });
            });
        } catch (err) {
            this.showToast('Erro ao carregar capturas: ' + err.message, 'error');
        }
    }

    async importNetworkCapture(e) {
        e.preventDefault();
        const form = e.target;
        const button = form.querySelector('button[type="submit"]');
        button.disabled = true;
        button.textContent = 'Importando...';
        try {
            const formData = new FormData(form);
            const result = await this.api('/api/network/import', {
                method: 'POST',
                headers: {'X-CSRF-Token': this.csrfToken},
                body: formData
            });
            this.showToast('Captura importada: ' + result.id, 'success');
            form.reset();
            document.getElementById('network-import-result').classList.remove('hidden');
            document.getElementById('network-import-result').textContent = JSON.stringify(result, null, 2);
            this.loadNetworkCaptures();
        } catch (error) {
            this.showToast('Erro na importação: ' + error.message, 'error');
        } finally {
            button.disabled = false;
            button.textContent = 'Importar';
        }
    }

    async showNetworkCaptureDetail(captureId) {
        try {
            const data = await this.api(`/api/network/captures/${captureId}`);
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Detalhes da Captura: ${this.escapeHtml(data.id)}</h3>
                <div class="grid grid-2">
                    <div>
                        <p><strong>Origem:</strong> ${this.escapeHtml(data.source)}</p>
                        <p><strong>Status:</strong> <span class="status status-${data.status}">${data.status}</span></p>
                        <p><strong>Interface:</strong> ${this.escapeHtml(data.interface_name || data.interface_id || '-')}</p>
                        <p><strong>Filtro de captura (BPF):</strong> ${this.escapeHtml(data.capture_filter || '-')}</p>
                        <p><strong>Filtro de exibição:</strong> ${this.escapeHtml(data.display_filter || '-')}</p>
                        <p><strong>Arquivo:</strong> ${this.escapeHtml(data.file_path)}</p>
                        <p><strong>Tamanho:</strong> ${data.file_size.toLocaleString()} bytes</p>
                        <p><strong>SHA-256:</strong> ${this.escapeHtml(data.file_sha256 || '-')}</p>
                        <p><strong>Pacotes:</strong> ${data.packet_count.toLocaleString()}</p>
                        <p><strong>Pacotes perdidos (captura):</strong> ${data.dropped_packets}</p>
                        <p><strong>Pacotes perdidos (interface):</strong> ${data.dropped_by_interface}</p>
                        <p><strong>TShark:</strong> ${this.escapeHtml(data.tshark_version || '-')}</p>
                        <p><strong>Dumpcap:</strong> ${this.escapeHtml(data.dumpcap_version || '-')}</p>
                        <p><strong>Ambiente:</strong> ${this.escapeHtml(data.environment)}</p>
                    </div>
                    <div>
                        <p><strong>Criada em:</strong> ${this.formatDate(data.created_at)}</p>
                        <p><strong>Iniciada em:</strong> ${this.formatDate(data.started_at)}</p>
                        <p><strong>Finalizada em:</strong> ${this.formatDate(data.finished_at)}</p>
                        ${data.error ? `<p><strong>Erro:</strong> <span class="job-error">${this.escapeHtml(data.error)}</span></p>` : ''}
                    </div>
                </div>
                <div class="actions" style="margin-top: 1rem;">
                    <button class="btn btn-secondary btn-small" onclick="app.loadNetworkPackets('${this.escapeHtml(data.id)}')">Ver Pacotes</button>
                    <button class="btn btn-secondary btn-small" onclick="app.loadNetworkStats('${this.escapeHtml(data.id)}')">Ver Estatísticas</button>
                    <button class="btn btn-secondary btn-small" onclick="app.loadNetworkReport('${this.escapeHtml(data.id)}')">Gerar Relatório</button>
                    <button class="btn btn-secondary btn-small" onclick="app.openNetworkInWireshark('${this.escapeHtml(data.id)}')">Abrir no Wireshark</button>
                </div>
            `;
        } catch (err) {
            this.showToast('Erro ao carregar detalhes: ' + err.message, 'error');
        }
    }

    async loadNetworkPackets(captureId) {
        try {
            const result = await this.api(`/api/network/captures/${captureId}/packets`, {
                method: 'POST',
                body: JSON.stringify({display_filter: '', offset: 0, limit: 100})
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Pacotes da Captura: ${this.escapeHtml(captureId)}</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr><th>#</th><th>Tempo (s)</th><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Tam.</th><th>Info</th></tr>
                        </thead>
                        <tbody>
                            ${result.packets.map(p => `
                                <tr data-packet="${p.number}" style="cursor: pointer;">
                                    <td>${p.number}</td>
                                    <td>${p.time.toFixed(6)}</td>
                                    <td>${this.escapeHtml(p.source)}</td>
                                    <td>${this.escapeHtml(p.destination)}</td>
                                    <td>${this.escapeHtml(p.protocol)}</td>
                                    <td>${p.length}</td>
                                    <td>${this.escapeHtml(p.info.slice(0, 120))}${p.info.length > 120 ? '...' : ''}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                <p>Clique em um pacote para ver detalhes.</p>
            `;
            panel.querySelectorAll('tbody tr').forEach(tr => {
                tr.addEventListener('click', () => {
                    this.loadNetworkPacketDetail(captureId, parseInt(tr.dataset.packet));
                });
            });
        } catch (err) {
            this.showToast('Erro ao carregar pacotes: ' + err.message, 'error');
        }
    }

    async loadNetworkPacketDetail(captureId, packetNumber) {
        try {
            const detail = await this.api(`/api/network/captures/${captureId}/packets/${packetNumber}`);
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Pacote #${detail.number} - Captura: ${this.escapeHtml(captureId)}</h3>
                <div class="grid grid-2">
                    <div>
                        <p><strong>Tempo:</strong> ${detail.time.toFixed(6)}s (${this.escapeHtml(detail.time_iso)})</p>
                        <p><strong>Origem:</strong> ${this.escapeHtml(detail.source)}</p>
                        <p><strong>Destino:</strong> ${this.escapeHtml(detail.destination)}</p>
                        <p><strong>Protocolo:</strong> ${this.escapeHtml(detail.protocol)}</p>
                        <p><strong>Tamanho:</strong> ${detail.length} bytes</p>
                        <p><strong>Info:</strong> ${this.escapeHtml(detail.info)}</p>
                    </div>
                    <div>
                        <button class="btn btn-secondary btn-small" onclick="app.loadNetworkPackets('${this.escapeHtml(captureId)}')">Voltar à lista</button>
                    </div>
                </div>
                ${detail.layers && detail.layers.length ? `
                    <h4>Árvore de Protocolos</h4>
                    <pre>${JSON.stringify(detail.layers, null, 2)}</pre>
                ` : ''}
                ${detail.hex_dump ? `
                    <h4>Hex Dump</h4>
                    <pre>${this.escapeHtml(detail.hex_dump)}</pre>
                ` : ''}
            `;
        } catch (err) {
            this.showToast('Erro ao carregar detalhes do pacote: ' + err.message, 'error');
        }
    }

    async loadNetworkStats(captureId) {
        try {
            const data = await this.api(`/api/network/captures/${captureId}/stats`, {
                method: 'POST',
                body: JSON.stringify({display_filter: ''})
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Estatísticas da Captura: ${this.escapeHtml(captureId)}</h3>
                <h4>Hierarquia de Protocolos</h4>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Protocolo</th><th>Pacotes</th><th>% Pacotes</th><th>Bytes</th><th>% Bytes</th></tr></thead>
                        <tbody>
                            ${data.protocol_stats.by_protocol.map(p => `
                                <tr>
                                    <td>${this.escapeHtml(p.protocol)}</td>
                                    <td>${p.packets.toLocaleString()}</td>
                                    <td>${p.percentage_packets.toFixed(1)}%</td>
                                    <td>${p.bytes.toLocaleString()}</td>
                                    <td>${p.percentage_bytes.toFixed(1)}%</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                <p>Total: ${data.protocol_stats.total_packets.toLocaleString()} pacotes, ${data.protocol_stats.total_bytes.toLocaleString()} bytes</p>

                <h4>Endpoints (Top 50)</h4>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Endereço</th><th>Tipo</th><th>RX Pkts</th><th>TX Pkts</th><th>RX Bytes</th><th>TX Bytes</th></tr></thead>
                        <tbody>
                            ${data.endpoints.map(e => `
                                <tr>
                                    <td>${this.escapeHtml(e.address)}</td>
                                    <td>${this.escapeHtml(e.type)}</td>
                                    <td>${e.packets_rx.toLocaleString()}</td>
                                    <td>${e.packets_tx.toLocaleString()}</td>
                                    <td>${e.bytes_rx.toLocaleString()}</td>
                                    <td>${e.bytes_tx.toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <h4>Conversações (Top 50)</h4>
                <div class="table-container">
                    <table>
                        <thead><tr><th>A ↔ B</th><th>Protocolo</th><th>Pacotes</th><th>Bytes</th><th>Duração (s)</th></tr></thead>
                        <tbody>
                            ${data.conversations.map(c => `
                                <tr>
                                    <td>${this.escapeHtml(c.endpoint_a)} ↔ ${this.escapeHtml(c.endpoint_b)}</td>
                                    <td>${this.escapeHtml(c.protocol)}</td>
                                    <td>${c.packets.toLocaleString()}</td>
                                    <td>${c.bytes.toLocaleString()}</td>
                                    <td>${c.duration.toFixed(3)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <h4>DNS</h4>
                <pre>${JSON.stringify(data.dns, null, 2)}</pre>

                <h4>TCP</h4>
                <pre>${JSON.stringify(data.tcp, null, 2)}</pre>
                <button class="btn btn-secondary btn-small" onclick="app.showNetworkCaptureDetail('${this.escapeHtml(captureId)}')">Voltar</button>
            `;
        } catch (err) {
            this.showToast('Erro ao carregar estatísticas: ' + err.message, 'error');
        }
    }

    async loadNetworkReport(captureId) {
        try {
            const data = await this.api(`/api/network/captures/${captureId}/report`, {
                method: 'POST',
                body: JSON.stringify({display_filter: ''})
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = `
                <h3>Relatório da Captura: ${this.escapeHtml(data.capture_id)}</h3>
                <div class="grid grid-2">
                    <div>
                        <p><strong>Pacotes:</strong> ${data.summary.packet_count.toLocaleString()}</p>
                        <p><strong>Protocolos:</strong> ${data.protocol_stats.by_protocol.length}</p>
                        <p><strong>Endpoints:</strong> ${data.endpoints.length}</p>
                        <p><strong>Conversações:</strong> ${data.conversations.length}</p>
                        <p><strong>Anomalias:</strong> ${data.anomalies.length}</p>
                    </div>
                    <div>
                        <p><strong>Origem:</strong> ${this.escapeHtml(data.summary.source)}</p>
                        <p><strong>Status:</strong> <span class="status status-${data.summary.status}">${data.summary.status}</span></p>
                        <p><strong>Tamanho do arquivo:</strong> ${data.summary.file_size.toLocaleString()} bytes</p>
                    </div>
                </div>
                <h4>Anomalias</h4>
                <ul>
                    ${data.anomalies.map(a => `<li>${this.escapeHtml(a)}</li>`).join('') || '<li>Nenhuma</li>'}
                </ul>
                <h4>Limitações</h4>
                <ul>
                    ${data.limitations.map(l => `<li>${this.escapeHtml(l)}</li>`).join('')}
                </ul>
                <button class="btn btn-secondary btn-small" onclick="app.showNetworkCaptureDetail('${this.escapeHtml(captureId)}')">Voltar</button>
            `;
        } catch (err) {
            this.showToast('Erro ao gerar relatório: ' + err.message, 'error');
        }
    }

    async openNetworkInWireshark(captureId) {
        try {
            await this.api(`/api/network/captures/${captureId}/open-wireshark`, {method: 'POST'});
            this.showToast('Wireshark iniciado', 'success');
        } catch (err) {
            this.showToast('Erro ao abrir Wireshark: ' + err.message, 'error');
        }
    }

    trackJob(jobId, type) {
        if (this.jobsPolling.has(jobId)) return;
        const interval = setInterval(async () => {
            try {
                const job = await this.api(`/api/jobs/${jobId}`);
                this.updateJobUI(job, type);
                if (['completed', 'failed', 'partial', 'cancelled', 'interrupted'].includes(job.status)) {
                    clearInterval(interval);
                    this.jobsPolling.delete(jobId);
                    if (job.status === 'completed') {
                        this.showToast(`${type} concluído com sucesso`, 'success');
                        if (type === 'scan') this.loadSessions();
                    } else {
                        this.showToast(`${type} falhou: ${job.error}`, 'error');
                    }
                }
            } catch (err) {
                clearInterval(interval);
                this.jobsPolling.delete(jobId);
            }
        }, 2000);
        this.jobsPolling.set(jobId, interval);
    }

    updateJobUI(job, type) {
        const container = document.getElementById(`${type}-jobs`);
        if (!container) return;

        let jobEl = container.querySelector(`[data-job-id="${job.id}"]`);
        if (!jobEl) {
            jobEl = document.createElement('div');
            jobEl.className = 'job-item';
            jobEl.dataset.jobId = job.id;
            container.prepend(jobEl);
        }

        jobEl.innerHTML = `
            <div class="job-header">
                <span class="job-type">${type === 'scan' ? 'Execução' : type === 'analyze' ? 'Análise IA' : 'Consulta OSINT'}</span>
                <span class="job-status status-${job.status}">${job.status}</span>
            </div>
            ${job.progress ? `<div class="job-progress">${this.escapeHtml(job.progress)}</div>` : ''}
            ${job.result ? `<div class="job-result">${this.escapeHtml(JSON.stringify(job.result, null, 2))}</div>` : ''}
            ${job.error ? `<div class="job-result job-error">Erro: ${this.escapeHtml(job.error)}</div>` : ''}
            ${['pending', 'running'].includes(job.status) ? '<button class="btn btn-secondary cancel-job">Cancelar</button>' : ''}
        `;
    }

    async configureOsintConnector(id) {
        const {connectors} = await this.api('/api/osint/connectors');
        const meta = connectors[id];
        if (!meta) return;
        const dialog = document.createElement('dialog');
        const form = document.createElement('form');
        const title = document.createElement('h3'); title.textContent = meta.name;
        form.appendChild(title);
        for (const field of meta.config.fields) {
            const label = document.createElement('label'); label.textContent = field.description;
            const input = document.createElement('input'); input.name = field.name;
            input.type = field.secret ? 'password' : 'text'; input.autocomplete = 'new-password';
            label.appendChild(input); form.appendChild(label);
        }
        const save = document.createElement('button'); save.textContent = 'Salvar'; save.type = 'submit';
        const cancel = document.createElement('button'); cancel.textContent = 'Cancelar'; cancel.type = 'button';
        cancel.onclick = () => { dialog.close(); dialog.remove(); };
        form.append(save, cancel); dialog.append(form); document.body.append(dialog);
        form.onsubmit = async (event) => {
            event.preventDefault();
            try {
                await this.api(`/api/config/osint/${encodeURIComponent(id)}`, {method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(form)))});
                form.reset(); dialog.close(); dialog.remove(); await this.loadConfigStatus();
            } catch (err) { this.showToast(err.message, 'error'); }
        };
        dialog.showModal();
    }

    startJobPolling() {
        this.api('/api/jobs').then(({jobs}) => {
            for (const job of jobs) {
                this.updateJobUI(job, job.type);
                if (['pending', 'running', 'cancelling'].includes(job.status)) this.trackJob(job.id, job.type);
            }
        }).catch(() => {});
    }

    async logout() {
        try {
            await this.api('/logout', { method: 'POST' });
            window.location.href = '/login';
        } catch (err) {
            window.location.href = '/login';
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }

    formatDate(isoString) {
        if (!isoString) return '-';
        try {
            return new Date(isoString).toLocaleString('pt-BR');
        } catch {
            return isoString;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }


}

const app = new SisifoApp();