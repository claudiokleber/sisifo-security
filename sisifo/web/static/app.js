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
        document.getElementById('osint-connector')?.addEventListener('change', (e) => this.updateOsintQueryTypeOptions(e));
        document.getElementById('osint-analyze-objective')?.addEventListener('click', () => this.analyzeOsintObjective());
        document.getElementById('osint-confirm-proposal')?.addEventListener('click', () => this.executeOsintProposal());
        document.getElementById('osint-reject-proposal')?.addEventListener('click', () => this.hideOsintProposal());
        document.getElementById('osint-execute-preview')?.addEventListener('click', () => this.executeOsintPreview());
        document.getElementById('osint-cancel-preview')?.addEventListener('click', () => this.hideOsintPreview());

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
                <div class="label">IA (${ai.configured ? 'configurada' : 'não configurada'})</div>
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
            this.osintConnectorsData = data.connectors;
            const select = document.getElementById('osint-connector');
            const previous = select.value;
            select.replaceChildren();
            const container = document.getElementById('osint-connectors'); container.replaceChildren();
            let ready = 0;
            for (const [id, meta] of Object.entries(data.connectors)) {
                const usable = meta.configured && meta.status !== 'planned';
                if (usable) ready++;
                const option = document.createElement('option'); option.value = id;
                option.disabled = !usable;
                option.textContent = `${meta.name} — ${id === 'dummy' ? 'demonstração' : usable ? 'pronto para consultar' : 'configuração necessária'}`;
                select.appendChild(option);
                const card = document.createElement('div'); card.className = 'osint-connector';
                const title = document.createElement('h4'); title.textContent = meta.name;
                const description = document.createElement('p');
                description.textContent = id === 'hibp' ? 'Verifica se um e-mail aparece em vazamentos conhecidos. Requer chave e plano compatível no HIBP.' : meta.description;
                const state = document.createElement('p'); state.textContent = usable ? 'Configuração salva. A consulta verificará o acesso ao serviço.' : 'Antes de começar, informe a chave de acesso deste serviço.';
                const configure = document.createElement('button'); configure.type = 'button'; configure.className = 'btn btn-secondary';
                configure.textContent = `${usable ? 'Editar configuração' : 'Configurar'} — ${meta.name}`;
                configure.addEventListener('click', () => this.configureOsintConnector(id));
                card.append(title, description, state, configure); container.appendChild(card);
            }
            if (data.connectors[previous]?.configured) select.value = previous;
            if (!ready) { const empty = document.createElement('option'); empty.textContent = 'Configure um serviço abaixo para começar'; empty.value = ''; select.prepend(empty); select.value = ''; }
            document.querySelector('#osint-query-form [type=submit]').disabled = !ready;
            document.getElementById('osint-status').textContent = ready ? 'Escolha um serviço e preencha a consulta. Nenhum dado será enviado sem sua confirmação.' : 'Ainda não há um serviço pronto. Use o botão Configurar nos cartões abaixo.';
            this.updateOsintQueryTypeOptions({target: select});
        } catch (err) {
            this.showToast('Não foi possível carregar os serviços. Atualize a página e tente novamente.', 'error');
        }
    }

    async submitOsintQuery(e) {
        e.preventDefault();
        const data = new FormData(e.target);
        await this.submitOsintQueryDirect(data.get('connector_id'), data.get('query'), data.get('query_type'));
    }

    // --- OSINT Interactive Methods ---

    updateOsintQueryTypeOptions(e) {
        const connectorId = e.target.value;
        const queryTypeSelect = document.getElementById('osint-query-type');
        const hintEl = document.getElementById('osint-query-hint');
        const helpEl = document.getElementById('osint-connector-help');
        
        if (!connectorId || !this.osintConnectorsData) {
            queryTypeSelect.innerHTML = '<option value="">Selecione um conector primeiro</option>';
            if (hintEl) hintEl.textContent = '';
            if (helpEl) helpEl.textContent = '';
            return;
        }

        const meta = this.osintConnectorsData[connectorId];
        if (!meta) return;

        const queryTypes = meta.query_types || [];
        queryTypeSelect.innerHTML = queryTypes.map(qt => `<option value="${qt}">${qt}</option>`).join('');

        // Update hints based on query type
        const hints = {
            'email': 'ex.: usuario@dominio.com',
            'domain': 'ex.: exemplo.com',
            'ip': 'ex.: 192.168.1.1 ou 2001:db8::1',
            'url': 'ex.: https://exemplo.com/path',
            'hash': 'ex.: hash MD5/SHA1/SHA256 (32/40/64 chars hex)',
        };
        const firstType = queryTypes[0];
        if (hintEl) hintEl.textContent = hints[firstType] || '';

        if (helpEl) {
            helpEl.textContent = `Tipos suportados: ${queryTypes.join(', ')} | ${meta.configured ? 'Configurado' : 'Configure na aba Configurações'}`;
        }

        // Show preview section
        this.hideOsintPreview();
        const input = document.getElementById('osint-query');
        input.type = firstType === 'email' ? 'email' : 'text';
        input.placeholder = hints[firstType] || 'Informe o valor da consulta';
    }

    showOsintPreview(connectorId, queryType) {
        const previewEl = document.getElementById('osint-preview');
        const detailsEl = document.getElementById('osint-preview-details');
        const connector = this.osintConnectorsData?.[connectorId];
        if (!connector || !previewEl || !detailsEl) return;

        detailsEl.innerHTML = `
            <p><strong>Serviço:</strong> ${this.escapeHtml(connector.name)}</p>
            <p><strong>Tipo de consulta:</strong> ${queryType}</p>
            <p><strong>Endpoint:</strong> ${connector.allowed_destinations?.join(', ') || 'N/A'}</p>
            <p><strong>Credencial:</strong> ${connector.configured ? 'Configurada' : '<span class="warning">Não configurada - configure na aba Configurações</span>'}</p>
            <p><strong>Rate limit local:</strong> ${connector.limits?.rate_per_minute || 'N/A'} req/min</p>
            <p class="dim">A consulta será enviada ao serviço externo acima. Nenhum dado sensível além do valor da consulta é transmitido.</p>
        `;
        previewEl.classList.remove('hidden');
    }

    hideOsintPreview() {
        document.getElementById('osint-preview')?.classList.add('hidden');
    }

    async executeOsintPreview() {
        const connectorId = document.getElementById('osint-connector').value;
        const queryType = document.getElementById('osint-query-type').value;
        const query = document.getElementById('osint-query').value;
        
        if (!connectorId || !queryType || !query) {
            this.showToast('Preencha todos os campos', 'warning');
            return;
        }

        this.hideOsintPreview();
        await this.submitOsintQueryDirect(connectorId, query, queryType);
    }

    async submitOsintQueryDirect(connectorId, query, queryType) {
        if (this.osintSubmitting) return;
        this.osintSubmitting = true;
        try {
            const proposal = await this.api('/api/osint/proposals', {method: 'POST', body: JSON.stringify({
                connector_id: connectorId, query, query_type: queryType
            })});
            if (!window.confirm(`Autorizar envio ao serviço OSINT?\nServiço: ${proposal.connector_id}\nDestino: ${proposal.destinations.join(', ')}\nTipo: ${proposal.query_type}\nConsulta: ${proposal.query}\n${proposal.cost}`)) return;
            const result = await this.api('/api/osint/query', {method: 'POST', body: JSON.stringify({
                proposal_id: proposal.proposal_id, confirmed: true
            })});
            this.showToast('Consulta OSINT iniciada', 'success');
            this.trackJob(result.job_id, 'osint');
        } catch (err) {
            this.showToast('Erro na consulta OSINT: ' + err.message, 'error');
        } finally { this.osintSubmitting = false; }
    }

    async analyzeOsintObjective() {
        const objective = document.getElementById('osint-objective').value.trim();
        if (!objective) {
            this.showToast('Descreva o objetivo da investigação', 'warning');
            return;
        }

        this.hideOsintProposal();
        const btn = document.getElementById('osint-analyze-objective');
        btn.disabled = true;
        btn.textContent = 'Analisando...';

        try {
            // Check if AI is configured
            const config = await this.api('/api/config/status');
            
            if (config.ai.configured && window.confirm(`Enviar o objetivo abaixo à IA configurada? Isso pode incluir o e-mail digitado e é separado da consulta HIBP.\n${objective}\nCancelar usa análise local.`)) {
                // Use AI to analyze objective and propose query
                await this.analyzeObjectiveWithAI(objective);
            } else {
                // Fallback: simple keyword matching for HIBP
                this.analyzeObjectiveLocally(objective);
            }
        } catch (err) {
            this.showToast('Erro ao analisar objetivo: ' + err.message, 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Analisar objetivo';
        }
    }

    analyzeObjectiveLocally(objective) {
        const lower = objective.toLowerCase();
        const proposalEl = document.getElementById('osint-proposal');
        const detailsEl = document.getElementById('osint-proposal-details');

        // Simple keyword matching
        let proposedConnector = null;
        let proposedType = 'email';
        let proposedQuery = '';
        let reasoning = '';

        if (lower.includes('e-mail') || lower.includes('email') || lower.includes('vazamento') || lower.includes('vazou') || lower.includes('pwned') || lower.includes('breach') || lower.includes('violação')) {
            proposedConnector = 'hibp';
            proposedType = 'email';
            reasoning = 'O objetivo menciona verificação de e-mail em vazamentos/violações. O HIBP (Have I Been Pwned) é o serviço adequado para consultar o endpoint breachedaccount.';
        }

        if (!proposedConnector) {
            detailsEl.innerHTML = '<p class="warning">Não foi possível identificar uma consulta. Descreva a verificação de um e-mail ou use o formulário guiado.</p>';
            proposalEl.classList.remove('hidden');
            return;
        }

        // Extract potential email from objective
        const emailMatch = objective.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (emailMatch) {
            proposedQuery = emailMatch[0];
        }

        this.renderOsintProposal(proposedConnector, proposedType, proposedQuery, reasoning);
    }

    renderOsintProposal(connectorId, queryType, query, reasoning) {
        const connector = this.osintConnectorsData?.[connectorId];
        if (!connector?.query_types?.includes(queryType) || typeof query !== 'string') return;
        const details = document.getElementById('osint-proposal-details');
        details.replaceChildren();
        for (const text of [
            `Serviço: ${connector.name}`, `Tipo: ${queryType}`, `Consulta: ${query || '(preencha o valor no formulário)'}`,
            `Justificativa: ${reasoning}`, `Destino: ${(connector.allowed_destinations || []).join(', ')}`,
            'Custo: consulte o plano do serviço; custo não estimado.',
            'A confirmação final será solicitada com os dados validados pelo servidor.'
        ]) {
            const p = document.createElement('p'); p.textContent = text; details.appendChild(p);
        }
        this.currentOsintProposal = {connectorId, queryType, query};
        document.getElementById('osint-proposal').classList.remove('hidden');
    }

    async analyzeObjectiveWithAI(objective) {
        try {
            // Use the existing AI chat endpoint to analyze the objective
            const response = await this.api('/api/ai/chat', {
                method: 'POST',
                body: JSON.stringify({
                    messages: [
                        {
                            role: 'user',
                            content: `Analise este objetivo de investigação OSINT e proponha uma consulta estruturada:

Objetivo: "${objective}"

Conectores OSINT disponíveis:
${Object.entries(this.osintConnectorsData || {}).map(([id, meta]) => `- ${id}: ${meta.name} (tipos: ${meta.query_types?.join(', ') || 'N/A'}, configurado: ${meta.configured ? 'sim' : 'não'})`).join('\n')}

Responda APENAS com JSON no formato:
{
  "connector_id": "id_do_conector",
  "query_type": "tipo_da_consulta",
  "query": "valor_sugerido_ou_vazio",
  "reasoning": "justificativa_curta",
  "estimated_cost": "gratuito|pode_consumir_creditos|desconhecido"
}

Não inclua texto adicional.`
                        }
                    ],
                    include_evidence: false
                })
            });

            // Parse AI response
            let proposal;
            try {
                const content = response.message?.content || response.content || '';
                const jsonMatch = content.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    proposal = JSON.parse(jsonMatch[0]);
                } else {
                    throw new Error('JSON não encontrado na resposta');
                }
            } catch (e) {
                console.error('Failed to parse AI proposal:', e);
                // Fallback to local analysis
                this.analyzeObjectiveLocally(objective);
                return;
            }

            // Validate proposal
            if (!proposal.connector_id || !this.osintConnectorsData?.[proposal.connector_id]) {
                this.analyzeObjectiveLocally(objective);
                return;
            }

            const connector = this.osintConnectorsData[proposal.connector_id];
            if (!connector.query_types?.includes(proposal.query_type)) {
                this.analyzeObjectiveLocally(objective);
                return;
            }

            if (typeof proposal.query !== 'string' || typeof proposal.reasoning !== 'string') {
                this.analyzeObjectiveLocally(objective); return;
            }
            this.renderOsintProposal(proposal.connector_id, proposal.query_type, proposal.query, proposal.reasoning);

        } catch (err) {
            console.error('AI analysis failed:', err);
            this.analyzeObjectiveLocally(objective);
        }
    }

    hideOsintProposal() {
        document.getElementById('osint-proposal')?.classList.add('hidden');
        this.currentOsintProposal = null;
    }

    executeOsintProposal() {
        const proposal = this.currentOsintProposal;
        if (!proposal) return;

        const query = proposal.query || document.getElementById('osint-query').value;
        if (!query) {
            this.showToast('Informe o valor da consulta', 'warning');
            return;
        }

        this.hideOsintProposal();
        this.submitOsintQueryDirect(proposal.connectorId, query, proposal.queryType);
    }

    async loadConfigStatus() {
        try {
            const config = await this.api('/api/config/status');
            document.getElementById('config-endpoint').value = config.ai.endpoint || '';
            document.getElementById('ai-connection-status').textContent = config.ai.configured ? 'Conexão salva. Use o teste para verificar disponibilidade atual.' : 'Conecte uma API para começar.';
            document.getElementById('config-model').value = config.ai.model || '';
            document.getElementById('chat-connection').textContent = config.ai.configured ? 'Modelo: ' + config.ai.model + ' · ' + config.ai.endpoint : 'IA desconectada. Abra Configurações para conectar sua API.';

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
        const button = form.querySelector('[type=submit]');
        button.disabled = true;
        try {
            const result = await this.api('/api/config/ai', {method: 'POST', body: JSON.stringify({
                endpoint: form.elements.endpoint.value, model: form.elements.model.value,
                api_key: form.elements.api_key.value || null
            })});
            form.elements.api_key.value = '';
            document.getElementById('ai-connection-status').textContent = 'Conexão testada com o modelo ' + result.model;
            this.showToast('Conexão testada e salva', 'success');
            document.getElementById('chat-connection').textContent = 'Modelo: ' + result.model + ' · ' + result.endpoint;
        } catch (err) {
            document.getElementById('ai-connection-status').textContent = err.message;
        } finally { button.disabled = false; }
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

    async loadNetworkPackets(captureId, options = {}) {
        const { displayFilter = '', offset = 0, limit = 100 } = options;
        // Store state for this capture
        this.networkState = this.networkState || {};
        this.networkState[captureId] = this.networkState[captureId] || { displayFilter: '', offset: 0, limit: 100 };
        this.networkState[captureId].displayFilter = displayFilter;
        this.networkState[captureId].offset = offset;
        this.networkState[captureId].limit = limit;

        try {
            const result = await this.api(`/api/network/captures/${captureId}/packets`, {
                method: 'POST',
                body: JSON.stringify({ display_filter: displayFilter, offset, limit })
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            const totalFiltered = result.total_filtered !== undefined ? result.total_filtered : result.packets.length;
            const hasMore = result.has_more !== undefined ? result.has_more : (offset + result.packets.length < totalFiltered);
            
            panel.innerHTML = `
                <h3>Pacotes da Captura: ${this.escapeHtml(captureId)}</h3>
                <div class="filter-bar">
                    <div class="filter-input-group">
                        <label for="packet-display-filter">Filtro de exibição (Wireshark):</label>
                        <input type="text" id="packet-display-filter" value="${this.escapeHtml(displayFilter)}" placeholder="ex.: tcp.port == 80 || dns">
                        <button id="packet-filter-apply" class="btn btn-primary btn-small">Aplicar</button>
                        <button id="packet-filter-clear" class="btn btn-secondary btn-small">Limpar</button>
                    </div>
                    <div class="pagination-controls">
                        <span class="pagination-info">Mostrando ${offset + 1}-${Math.min(offset + limit, totalFiltered)} de ${totalFiltered}</span>
                        <button id="packet-prev-page" class="btn btn-secondary btn-small" ${offset === 0 ? 'disabled' : ''}>Anterior</button>
                        <button id="packet-next-page" class="btn btn-secondary btn-small" ${!hasMore ? 'disabled' : ''}>Próxima</button>
                        <label for="packet-page-size">Por página:</label>
                        <select id="packet-page-size">
                            <option value="25" ${limit === 25 ? 'selected' : ''}>25</option>
                            <option value="50" ${limit === 50 ? 'selected' : ''}>50</option>
                            <option value="100" ${limit === 100 ? 'selected' : ''}>100</option>
                            <option value="200" ${limit === 200 ? 'selected' : ''}>200</option>
                        </select>
                    </div>
                </div>
                <div class="table-container">
                    <table id="network-packets-table">
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
            `;
            
            // Bind filter events
            document.getElementById('packet-filter-apply')?.addEventListener('click', () => {
                const filter = document.getElementById('packet-display-filter').value;
                this.loadNetworkPackets(captureId, { displayFilter: filter, offset: 0, limit: this.networkState[captureId].limit });
            });
            document.getElementById('packet-filter-clear')?.addEventListener('click', () => {
                document.getElementById('packet-display-filter').value = '';
                this.loadNetworkPackets(captureId, { displayFilter: '', offset: 0, limit: this.networkState[captureId].limit });
            });
            document.getElementById('packet-prev-page')?.addEventListener('click', () => {
                if (this.networkState[captureId].offset > 0) {
                    this.loadNetworkPackets(captureId, { 
                        displayFilter: this.networkState[captureId].displayFilter,
                        offset: Math.max(0, this.networkState[captureId].offset - this.networkState[captureId].limit),
                        limit: this.networkState[captureId].limit
                    });
                }
            });
            document.getElementById('packet-next-page')?.addEventListener('click', () => {
                this.loadNetworkPackets(captureId, { 
                    displayFilter: this.networkState[captureId].displayFilter,
                    offset: this.networkState[captureId].offset + this.networkState[captureId].limit,
                    limit: this.networkState[captureId].limit
                });
            });
            document.getElementById('packet-page-size')?.addEventListener('change', (e) => {
                this.loadNetworkPackets(captureId, { 
                    displayFilter: this.networkState[captureId].displayFilter,
                    offset: 0,
                    limit: parseInt(e.target.value)
                });
            });
            document.getElementById('packet-display-filter')?.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    document.getElementById('packet-filter-apply').click();
                }
            });

            panel.querySelectorAll('#network-packets-table tbody tr').forEach(tr => {
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
            const state = this.networkState?.[captureId] || { displayFilter: '', offset: 0, limit: 100 };
            
            // Build panel safely using DOM manipulation instead of innerHTML
            panel.innerHTML = ''; // Clear first
            
            const h3 = document.createElement('h3');
            h3.textContent = `Pacote #${detail.number} - Captura: ${captureId}`;
            panel.appendChild(h3);
            
            const grid = document.createElement('div');
            grid.className = 'grid grid-2';
            
            // Left column - packet info
            const leftDiv = document.createElement('div');
            const origLen = detail.original_length != null && detail.original_length > 0 ? detail.original_length : detail.length;
            const capLen = detail.captured_length != null && detail.captured_length > 0 ? detail.captured_length : detail.length;
            const fields = [
                { label: 'Tempo:', value: `${detail.time.toFixed(6)}s (${detail.time_iso || ""})` },
                { label: 'Origem:', value: detail.source },
                { label: 'Destino:', value: detail.destination },
                { label: 'Protocolo:', value: detail.protocol },
                { label: 'Comprimento no fio:', value: `${origLen} bytes` },
                { label: 'Comprimento capturado:', value: `${capLen} bytes` },
                { label: 'Info:', value: detail.info }
            ];
            fields.forEach(f => {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = f.label;
                p.appendChild(strong);
                p.appendChild(document.createTextNode(' ' + f.value));
                leftDiv.appendChild(p);
            });
            grid.appendChild(leftDiv);
            
            // Right column - back button
            const rightDiv = document.createElement('div');
            const backBtn = document.createElement('button');
            backBtn.className = 'btn btn-secondary btn-small';
            backBtn.textContent = 'Voltar à lista';
            backBtn.addEventListener('click', () => this.loadNetworkPackets(captureId, state));
            rightDiv.appendChild(backBtn);
            grid.appendChild(rightDiv);
            
            panel.appendChild(grid);

            // Truncation banner
            if (capLen < origLen) {
                const truncBanner = document.createElement('div');
                truncBanner.className = 'alert alert-warning';
                truncBanner.textContent = `Aviso: captura truncada. ${capLen} bytes capturados de ${origLen} bytes no fio.`;
                panel.appendChild(truncBanner);
            }
            
            // Protocol tree - use textContent to prevent XSS
            if (detail.layers && detail.layers.length) {
                const h4 = document.createElement('h4');
                h4.textContent = 'Árvore de Protocolos';
                panel.appendChild(h4);
                
                const pre = document.createElement('pre');
                pre.textContent = JSON.stringify(detail.layers, null, 2);
                panel.appendChild(pre);
            }
            
            // Hex dump section
            const hexHeading = document.createElement('h4');
            hexHeading.textContent = 'Hex Dump';
            panel.appendChild(hexHeading);

            if (detail.hex_dump_error) {
                const errBox = document.createElement('div');
                errBox.className = 'alert alert-error';
                errBox.textContent = "Falha na extração de hex dump: " + detail.hex_dump_error;
                panel.appendChild(errBox);
            }

            if (detail.hex_dump) {
                if (detail.extracted_length != null && detail.extracted_length > 0) {
                    const extractedInfo = document.createElement('p');
                    extractedInfo.className = 'text-muted';
                    const isPartial = capLen && detail.extracted_length < capLen;
                    extractedInfo.textContent = `Bytes extraídos: ${detail.extracted_length}${isPartial ? " (parcial)" : ""}`;
                    panel.appendChild(extractedInfo);
                }
                const pre = document.createElement('pre');
                pre.textContent = detail.hex_dump;
                panel.appendChild(pre);
            } else if (!detail.hex_dump_error) {
                const emptyNotice = document.createElement('p');
                emptyNotice.className = 'text-muted';
                emptyNotice.textContent = 'Nenhum dado de hex dump disponível para este pacote.';
                panel.appendChild(emptyNotice);
            }
        } catch (err) {
            this.showToast('Erro ao carregar detalhes do pacote: ' + err.message, 'error');
        }
    }

    async loadNetworkStats(captureId) {
        try {
            const state = this.networkState?.[captureId] || { displayFilter: '', offset: 0, limit: 100 };
            const data = await this.api(`/api/network/captures/${captureId}/stats`, {
                method: 'POST',
                body: JSON.stringify({ display_filter: state.displayFilter })
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = ''; // Clear
            
            // Header
            const h3 = document.createElement('h3');
            h3.textContent = `Estatísticas da Captura: ${captureId}`;
            panel.appendChild(h3);
            
            if (state.displayFilter) {
                const p = document.createElement('p');
                p.className = 'filter-applied';
                p.textContent = `Filtrado por: ${state.displayFilter}`;
                panel.appendChild(p);
            }
            
            // Protocol hierarchy
            const h4a = document.createElement('h4');
            h4a.textContent = 'Hierarquia de Protocolos';
            panel.appendChild(h4a);
            
            const tableContainer1 = document.createElement('div');
            tableContainer1.className = 'table-container';
            const table1 = document.createElement('table');
            const thead1 = document.createElement('thead');
            thead1.innerHTML = '<tr><th>Protocolo</th><th>Pacotes</th><th>% Pacotes</th><th>Bytes</th><th>% Bytes</th></tr>';
            table1.appendChild(thead1);
            const tbody1 = document.createElement('tbody');
            data.protocol_stats.by_protocol.forEach(p => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${this.escapeHtml(p.protocol)}</td><td>${p.packets.toLocaleString()}</td><td>${p.percentage_packets.toFixed(1)}%</td><td>${p.bytes.toLocaleString()}</td><td>${p.percentage_bytes.toFixed(1)}%</td>`;
                tbody1.appendChild(tr);
            });
            table1.appendChild(tbody1);
            tableContainer1.appendChild(table1);
            panel.appendChild(tableContainer1);
            
            const p1 = document.createElement('p');
            p1.textContent = `Total: ${data.protocol_stats.total_packets.toLocaleString()} pacotes, ${data.protocol_stats.total_bytes.toLocaleString()} bytes`;
            panel.appendChild(p1);
            
            // Endpoints
            const h4b = document.createElement('h4');
            h4b.textContent = 'Endpoints (Top 50)';
            panel.appendChild(h4b);
            
            const tableContainer2 = document.createElement('div');
            tableContainer2.className = 'table-container';
            const table2 = document.createElement('table');
            const thead2 = document.createElement('thead');
            thead2.innerHTML = '<tr><th>Endereço</th><th>Tipo</th><th>RX Pkts</th><th>TX Pkts</th><th>RX Bytes</th><th>TX Bytes</th></tr>';
            table2.appendChild(thead2);
            const tbody2 = document.createElement('tbody');
            data.endpoints.forEach(e => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${this.escapeHtml(e.address)}</td><td>${this.escapeHtml(e.type)}</td><td>${e.packets_rx.toLocaleString()}</td><td>${e.packets_tx.toLocaleString()}</td><td>${e.bytes_rx.toLocaleString()}</td><td>${e.bytes_tx.toLocaleString()}</td>`;
                tbody2.appendChild(tr);
            });
            table2.appendChild(tbody2);
            tableContainer2.appendChild(table2);
            panel.appendChild(tableContainer2);
            
            // Conversations
            const h4c = document.createElement('h4');
            h4c.textContent = 'Conversações (Top 50)';
            panel.appendChild(h4c);
            
            const tableContainer3 = document.createElement('div');
            tableContainer3.className = 'table-container';
            const table3 = document.createElement('table');
            const thead3 = document.createElement('thead');
            thead3.innerHTML = '<tr><th>A <=> B</th><th>Protocolo</th><th>Pacotes</th><th>Bytes</th><th>Duração (s)</th></tr>';
            table3.appendChild(thead3);
            const tbody3 = document.createElement('tbody');
            data.conversations.forEach(c => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${this.escapeHtml(c.endpoint_a)} <=> ${this.escapeHtml(c.endpoint_b)}</td><td>${this.escapeHtml(c.protocol)}</td><td>${c.packets.toLocaleString()}</td><td>${c.bytes.toLocaleString()}</td><td>${c.duration.toFixed(3)}</td>`;
                tbody3.appendChild(tr);
            });
            table3.appendChild(tbody3);
            tableContainer3.appendChild(table3);
            panel.appendChild(tableContainer3);
            
            // DNS
            const h4d = document.createElement('h4');
            h4d.textContent = 'DNS';
            panel.appendChild(h4d);
            const pre1 = document.createElement('pre');
            pre1.textContent = JSON.stringify(data.dns, null, 2);
            panel.appendChild(pre1);
            
            // TCP
            const h4e = document.createElement('h4');
            h4e.textContent = 'TCP';
            panel.appendChild(h4e);
            const pre2 = document.createElement('pre');
            pre2.textContent = JSON.stringify(data.tcp, null, 2);
            panel.appendChild(pre2);
            
            // Back button
            const backBtn = document.createElement('button');
            backBtn.className = 'btn btn-secondary btn-small';
            backBtn.textContent = 'Voltar';
            backBtn.addEventListener('click', () => this.showNetworkCaptureDetail(captureId));
            panel.appendChild(backBtn);
            
        } catch (err) {
            this.showToast('Erro ao carregar estatísticas: ' + err.message, 'error');
        }
    }

    async loadNetworkReport(captureId) {
        try {
            const state = this.networkState?.[captureId] || { displayFilter: '', offset: 0, limit: 100 };
            const data = await this.api(`/api/network/captures/${captureId}/report`, {
                method: 'POST',
                body: JSON.stringify({ display_filter: state.displayFilter })
            });
            const panel = document.getElementById('network-capture-detail');
            panel.classList.remove('hidden');
            panel.innerHTML = '';
            
            const h3 = document.createElement('h3');
            h3.textContent = `Relatório da Captura: ${data.capture_id}`;
            panel.appendChild(h3);
            
            if (state.displayFilter) {
                const p = document.createElement('p');
                p.className = 'filter-applied';
                p.textContent = `Filtrado por: ${state.displayFilter}`;
                panel.appendChild(p);
            }
            
            const grid = document.createElement('div');
            grid.className = 'grid grid-2';
            
            const leftDiv = document.createElement('div');
            const leftFields = [
                { label: 'Pacotes:', value: data.summary.packet_count.toLocaleString() },
                { label: 'Protocolos:', value: data.protocol_stats.by_protocol.length.toString() },
                { label: 'Endpoints:', value: data.endpoints.length.toString() },
                { label: 'Conversações:', value: data.conversations.length.toString() },
                { label: 'Anomalias:', value: data.anomalies.length.toString() }
            ];
            leftFields.forEach(f => {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = f.label;
                p.appendChild(strong);
                p.appendChild(document.createTextNode(' ' + f.value));
                leftDiv.appendChild(p);
            });
            grid.appendChild(leftDiv);
            
            const rightDiv = document.createElement('div');
            const rightFields = [
                { label: 'Origem:', value: data.summary.source },
                { label: 'Status:', value: data.summary.status },
                { label: 'Tamanho do arquivo:', value: `${data.summary.file_size.toLocaleString()} bytes` }
            ];
            rightFields.forEach(f => {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = f.label;
                p.appendChild(strong);
                p.appendChild(document.createTextNode(' ' + f.value));
                rightDiv.appendChild(p);
            });
            grid.appendChild(rightDiv);
            panel.appendChild(grid);
            
            // Anomalies
            const h4a = document.createElement('h4');
            h4a.textContent = 'Anomalias';
            panel.appendChild(h4a);
            const ul1 = document.createElement('ul');
            if (data.anomalies.length === 0) {
                const li = document.createElement('li');
                li.textContent = 'Nenhuma';
                ul1.appendChild(li);
            } else {
                data.anomalies.forEach(a => {
                    const li = document.createElement('li');
                    li.textContent = a;
                    ul1.appendChild(li);
                });
            }
            panel.appendChild(ul1);
            
            // Limitations
            const h4b = document.createElement('h4');
            h4b.textContent = 'Limitações';
            panel.appendChild(h4b);
            const ul2 = document.createElement('ul');
            data.limitations.forEach(l => {
                const li = document.createElement('li');
                li.textContent = l;
                ul2.appendChild(li);
            });
            panel.appendChild(ul2);
            
            // Back button
            const backBtn = document.createElement('button');
            backBtn.className = 'btn btn-secondary btn-small';
            backBtn.textContent = 'Voltar';
            backBtn.addEventListener('click', () => this.showNetworkCaptureDetail(captureId));
            panel.appendChild(backBtn);
            
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
        this.updateJobUI({id: jobId, status: 'pending'}, type);
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
                        this.showToast(`${job.status === 'cancelled' ? 'Operação cancelada' : 'Não foi possível concluir. Veja as orientações no resultado.'}`, 'error');
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
        const container = document.getElementById(`${type === 'osint-ai' ? 'osint' : type}-jobs`);
        if (!container) return;

        let jobEl = container.querySelector(`[data-job-id="${job.id}"]`);
        if (!jobEl) {
            jobEl = document.createElement('div');
            jobEl.className = 'job-item';
            jobEl.dataset.jobId = job.id;
            container.prepend(jobEl);
        }

        if (type === 'osint' || type === 'osint-ai') {
            this.renderOsintJob(jobEl, job, type); return;
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
        if (type === 'osint' && job.status === 'completed' && job.result?.results?.length) {
            this.addOsintInterpretation(jobEl, job);
        }
    }

    renderOsintJob(container, job, type) {
        container.replaceChildren();
        const title = document.createElement('h4'); title.textContent = type === 'osint-ai' ? 'Explicação da IA' : 'Verificação de informações';
        const status = document.createElement('p');
        status.textContent = ({pending:'Na fila. Aguarde…', running:'Consultando. Você pode cancelar abaixo.', cancelling:'Cancelando…', completed:'Concluída', cancelled:'Cancelada por você.', failed:'Não foi possível concluir.', partial:'Resultado incompleto.', interrupted:'Interrompida após reiniciar o sistema.'})[job.status] || job.status;
        container.append(title, status);
        const add = text => { const p = document.createElement('p'); p.textContent = text; container.appendChild(p); };
        if (job.status === 'failed') {
            const messages = {AUTHENTICATION_FAILED:'A chave foi recusada. Edite a configuração do serviço e confira a chave.', ACCESS_FORBIDDEN:'O serviço negou acesso. Confira as permissões e a assinatura contratada.', RATE_LIMIT_EXCEEDED:'O limite de consultas foi atingido. Aguarde antes de tentar novamente.', NETWORK_ERROR:'Não foi possível conectar ao serviço. Verifique sua conexão e tente mais tarde.', INVALID_JSON:'O serviço retornou uma resposta incompatível. Tente novamente mais tarde.'};
            add(messages[job.result?.error_code] || job.error || 'Verifique a configuração e a disponibilidade do serviço.');
            if (job.result?.retry_after) add(`Aguarde pelo menos ${job.result.retry_after} segundos.`);
        }
        if (job.result?.content) add(job.result.content);
        if (job.status === 'completed' && type === 'osint') {
            const results = job.result?.results || [];
            add(results.length ? `${results.length} ocorrência(s) encontrada(s). Isso não confirma acesso atual à sua conta.` : 'Nenhuma ocorrência encontrada nesta fonte. Isso não garante ausência de exposição.');
            results.forEach((r, i) => {
                const e = r.evidence || {};
                add(`${i + 1}. ${e.hibp_title || e.hibp_breach_name || r.source}${e.hibp_breach_date ? ' — ' + e.hibp_breach_date : ''}`);
                if (e.hibp_data_classes?.length) add('Dados envolvidos: ' + e.hibp_data_classes.map(x => ({'Email addresses':'Endereços de e-mail','Passwords':'Senhas','Phone numbers':'Telefones','IP addresses':'Endereços IP','Usernames':'Nomes de usuário'})[x] || x).join(', '));
                for (const text of [...(r.warnings || []), ...(r.limitations || [])]) add(text);
            });
            if (results.length) this.addOsintInterpretation(container, job);
        }
        if (['pending','running'].includes(job.status)) {
            const cancel = document.createElement('button'); cancel.textContent = 'Cancelar consulta'; cancel.className = 'btn btn-secondary cancel-job'; container.appendChild(cancel);
        }
        if (job.result) {
            const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Ver detalhes técnicos';
            const pre = document.createElement('pre'); pre.textContent = JSON.stringify(job.result, null, 2); details.append(summary, pre); container.appendChild(details);
        }
    }

    addOsintInterpretation(container, job) {
        const group = document.createElement('div');
        group.className = 'osint-ai-selection';
        group.textContent = 'Quer entender melhor? Selecione resultados para uma explicação opcional pela IA. Você verá os dados antes de enviá-los.';
        const checks = [];
        job.result.results.forEach((result, index) => {
            const label = document.createElement('label');
            const check = document.createElement('input'); check.type = 'checkbox';
            checks.push(check); label.appendChild(check);
            label.appendChild(document.createTextNode(`Resultado ${index + 1}: ${result.source} — ${result.evidence?.hibp_breach_name || 'evidência'}`));
            group.appendChild(label);
        });
        const button = document.createElement('button'); button.textContent = 'Revisar dados para a IA'; button.disabled = true; button.className = 'btn btn-secondary';
        checks.forEach(c => c.addEventListener('change', () => { button.disabled = !checks.some(x => x.checked); }));
        const previewBox = document.createElement('div');
        button.addEventListener('click', async () => {
            button.disabled = true; previewBox.replaceChildren();
            try {
                const indices = checks.flatMap((c, i) => c.checked ? [i] : []);
                const response = await this.api('/api/osint/ai/preview', {method: 'POST', body: JSON.stringify({job_id: job.id, indices})});
                const preview = document.createElement('pre'); preview.textContent = JSON.stringify(JSON.parse(response.preview), null, 2);
                const destination = document.createElement('p'); destination.textContent = `Destino: ${response.destination}. Envio separado da consulta OSINT.`;
                const send = document.createElement('button'); send.textContent = 'Autorizar envio desta prévia à IA';
                send.addEventListener('click', async () => {
                    send.disabled = true;
                    try {
                        const result = await this.api('/api/osint/ai/interpret', {method: 'POST', body: JSON.stringify({proposal_id: response.proposal_id, confirmed: true})});
                        this.trackJob(result.job_id, 'osint-ai');
                    } catch (err) { this.showToast(err.message, 'error'); send.disabled = false; }
                });
                previewBox.append(destination, preview, send);
            } catch (err) { this.showToast(err.message, 'error'); }
            finally { button.disabled = !checks.some(x => x.checked); }
        });
        group.append(button, previewBox); container.appendChild(group);
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
            const input = document.createElement('input'); input.name = field.name; input.required = true;
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
                form.reset(); dialog.close(); dialog.remove(); await this.loadConfigStatus(); await this.loadOsintConnectors(); this.showToast('Configuração salva. Agora você pode fazer uma consulta.', 'success');
            } catch (err) { this.showToast(err.message, 'error'); }
        };
        dialog.showModal();
    }

    startJobPolling() {
        this.api('/api/jobs').then(({jobs}) => {
            for (const job of [...jobs].reverse()) {
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

// Conversation stays in memory; responses are rendered as text, never HTML.
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('ai-offline').addEventListener('click', async () => {
        try {
            await app.api('/api/config/ai', {method: 'POST', body: JSON.stringify({provider: 'export'})});
            document.getElementById('config-api-key').value = '';
            document.getElementById('chat-connection').textContent = 'IA desconectada. Modo offline.';
            document.getElementById('ai-connection-status').textContent = 'Modo offline. Nenhuma consulta de IA será enviada.';
        } catch (err) { app.showToast(err.message, 'error'); }
    });
    let history = [];
    let previewSession = null;
    let busy = false;
    const status = document.getElementById('chat-status');
    const session = document.getElementById('chat-session');
    const consent = document.getElementById('chat-consent');
    const log = document.getElementById('chat-messages');
    function render() {
        log.replaceChildren();
        for (const message of history) {
            const item = document.createElement('p');
            item.style.whiteSpace = 'pre-wrap';
            item.className = message.role === 'user' ? 'ai-message-user' : 'ai-message-assistant';
            item.textContent = (message.role === 'user' ? 'Você: ' : 'IA: ') + message.content;
            log.appendChild(item);
        }
    }
    session.addEventListener('input', () => {
        previewSession = null; consent.checked = false;
        history = []; render();
        document.getElementById('chat-context').classList.add('hidden');
    });
    document.getElementById('ai-discover').addEventListener('click', async (event) => {
        const button = event.target;
        button.disabled = true;
        const state = document.getElementById('ai-connection-status');
        state.textContent = 'Consultando catálogo da API…';
        try {
            const result = await app.api('/api/ai/models', {method: 'POST', body: JSON.stringify({
                endpoint: document.getElementById('config-endpoint').value,
                api_key: document.getElementById('config-api-key').value || null
            })});
            const list = document.getElementById('ai-models');
            list.replaceChildren();
            for (const model of result.models) {
                const option = document.createElement('option');
                option.value = model; list.appendChild(option);
            }
            state.textContent = result.models.length + ' modelos encontrados. Escolha um modelo abaixo e teste a conexão.';
        } catch (err) { state.textContent = err.message + ' Você pode informar um modelo manualmente.'; }
        finally { button.disabled = false; }
    });
    document.getElementById('chat-preview').addEventListener('click', async () => {
        const id = session.value.trim();
        try {
            const data = await app.api('/api/analyze/preview', {method: 'POST', body: JSON.stringify({session_id: id})});
            if (session.value.trim() !== id) return;
            const pre = document.getElementById('chat-context');
            pre.textContent = JSON.stringify(data, null, 2); pre.classList.remove('hidden');
            previewSession = id; consent.checked = false;
        } catch (err) { status.textContent = err.message; }
    });
    document.getElementById('chat-clear').addEventListener('click', () => {
        if (busy) return;
        history = []; render(); status.textContent = 'Nova conversa.';
    });
    document.getElementById('ai-chat-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        if (busy) return;
        const id = session.value.trim();
        if (id && (previewSession !== id || !consent.checked)) {
            status.textContent = 'Revise o contexto e autorize seu envio antes de conversar com esta sessão.'; return;
        }
        const input = document.getElementById('chat-input');
        const message = {role: 'user', content: input.value};
        busy = true; session.disabled = true; status.textContent = 'Aguardando resposta…';
        const submit = event.target.querySelector('[type=submit]'); submit.disabled = true;
        try {
            const result = await app.api('/api/ai/chat', {method: 'POST', body: JSON.stringify({
                messages: [...history, message], session_id: id || null, include_evidence: Boolean(id && consent.checked)
            })});
            history.push(message, {role: 'assistant', content: result.content});
            render(); input.value = ''; status.textContent = 'Modelo: ' + result.model;
        } catch (err) { status.textContent = err.message; }
        finally { busy = false; session.disabled = false; submit.disabled = false; }
    });
});
