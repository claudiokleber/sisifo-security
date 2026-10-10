const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
    constructor() { this.children = []; this.classList = {remove() {}, add() {}}; }
    set innerHTML(_) { throw Error('Unexpected HTML rendering'); }
    replaceChildren() { this.children = []; }
    appendChild(child) { this.children.push(child); }
    append(...children) { this.children.push(...children); }
}
const elements = new Map();
const sandbox = {console, document: {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
    createElement() { return new Element(); }
}, window: {confirm: () => false}};
vm.createContext(sandbox);
const source = fs.readFileSync('sisifo/web/static/app.js', 'utf8').split('const app = new SisifoApp();')[0];
vm.runInContext(source + '\nthis.App = SisifoApp;', sandbox);
(async () => {
    const app = Object.create(sandbox.App.prototype);
    app.osintConnectorsData = {hibp: {name: 'HIBP', query_types: ['email'], allowed_destinations: ['haveibeenpwned.com']}};
    const calls = [];
    app.showToast = () => {};
    app.trackJob = (id) => calls.push(id);
    app.api = async () => ({content: JSON.stringify({connector_id: 'hibp', query_type: 'email', query: 'test@example.com', reasoning: '<img src=x onerror=alert(1)>', estimated_cost: '<script>bad()</script>'})});
    await app.analyzeObjectiveWithAI('email test@example.com');
    assert.equal(app.currentOsintProposal.queryType, 'email');
    const text = elements.get('osint-proposal-details').children.map(c => c.textContent).join('\n');
    assert(text.includes('<img src=x onerror=alert(1)>'));
    assert(!text.includes('<script>'));
    app.api = async (url, options) => {
        calls.push(url);
        if (url.endsWith('proposals')) return {proposal_id: 'token', connector_id: 'hibp', query: 'test@example.com', query_type: 'email', destinations: ['haveibeenpwned.com'], cost: 'desconhecido'};
        assert.deepEqual(JSON.parse(options.body), {proposal_id: 'token', confirmed: true});
        return {job_id: 'job'};
    };
    await app.submitOsintQueryDirect('hibp', 'test@example.com', 'email');
    assert.deepEqual(calls, ['/api/osint/proposals']);
    calls.length = 0;
    sandbox.window.confirm = () => true;
    await app.submitOsintQueryDirect('hibp', 'test@example.com', 'email');
    assert.deepEqual(calls, ['/api/osint/proposals', '/api/osint/query', 'job']);
    const container = new Element();
    app.renderOsintJob(container, {status:'failed', result:{error_code:'AUTHENTICATION_FAILED'}}, 'osint');
    assert(container.children.some(x => String(x.textContent).includes('A chave foi recusada')));
    app.renderOsintJob(container, {status:'completed', result:{results:[]}}, 'osint');
    assert(container.children.some(x => String(x.textContent).includes('não garante ausência')));
    console.log('OSINT UI contracts passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
