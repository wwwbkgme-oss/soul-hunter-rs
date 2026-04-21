/**
 * Soul Hunter Dashboard - Production-Ready WebSocket Client
 * 
 * Features:
 * - Real-time WebSocket connection with auto-reconnect
 * - Session management and progress tracking
 * - Finding discovery and filtering
 * - Responsive UI with view switching
 * - Toast notifications for events
 */

// Configuration
const CONFIG = {
    WS_URL: `ws://${window.location.host}/ws`,
    API_URL: `/api/v1`,
    RECONNECT_INTERVAL: 3000,
    MAX_RECONNECT_ATTEMPTS: 10,
    HEARTBEAT_INTERVAL: 30000,
};

// State
const state = {
    ws: null,
    connected: false,
    reconnectAttempts: 0,
    reconnectTimer: null,
    heartbeatTimer: null,
    sessions: new Map(),
    findings: [],
    activities: [],
    currentView: 'dashboard',
    subscriptions: new Set(),
};

// DOM Elements
const elements = {
    connectionStatus: document.getElementById('connectionStatus'),
    activeSessions: document.getElementById('activeSessions'),
    totalFindings: document.getElementById('totalFindings'),
    criticalFindings: document.getElementById('criticalFindings'),
    highFindings: document.getElementById('highFindings'),
    sessionsTableBody: document.getElementById('sessionsTableBody'),
    allSessionsTableBody: document.getElementById('allSessionsTableBody'),
    findingsTableBody: document.getElementById('findingsTableBody'),
    activityList: document.getElementById('activityList'),
    severityChart: document.getElementById('severityChart'),
    toastContainer: document.getElementById('toastContainer'),
    navLinks: document.querySelectorAll('.nav-link'),
    views: document.querySelectorAll('.view'),
};

// Severity colors mapping
const SEVERITY_COLORS = {
    critical: '#f85149',
    high: '#ffa657',
    medium: '#d29922',
    low: '#58a6ff',
    info: '#8b949e',
};

// Status mapping
const STATUS_LABELS = {
    created: 'Created',
    queued: 'Queued',
    running: 'Running',
    paused: 'Paused',
    completed: 'Completed',
    failed: 'Failed',
    cancelled: 'Cancelled',
};

/**
 * Initialize the dashboard
 */
function init() {
    console.log('Soul Hunter Dashboard initializing...');
    
    // Setup navigation
    setupNavigation();
    
    // Setup event listeners
    setupEventListeners();
    
    // Connect WebSocket
    connectWebSocket();
    
    // Load initial data
    loadInitialData();
    
    console.log('Soul Hunter Dashboard initialized');
}

/**
 * Setup navigation links
 */
function setupNavigation() {
    elements.navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = link.dataset.view;
            switchView(view);
        });
    });
}

/**
 * Switch between views
 */
function switchView(viewName) {
    // Update nav
    elements.navLinks.forEach(link => {
        link.classList.toggle('active', link.dataset.view === viewName);
    });
    
    // Update views
    elements.views.forEach(view => {
        view.classList.toggle('active', view.id === `${viewName}View`);
    });
    
    state.currentView = viewName;
    
    // Refresh data for the new view
    if (viewName === 'sessions') {
        requestSessions();
    } else if (viewName === 'findings') {
        requestFindings();
    }
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Refresh button
    const refreshBtn = document.getElementById('refreshSessions');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', requestSessions);
    }
    
    // Filters
    const statusFilter = document.getElementById('statusFilter');
    if (statusFilter) {
        statusFilter.addEventListener('change', filterSessions);
    }
    
    const severityFilter = document.getElementById('severityFilter');
    if (severityFilter) {
        severityFilter.addEventListener('change', filterFindings);
    }
    
    const sessionSearch = document.getElementById('sessionSearch');
    if (sessionSearch) {
        sessionSearch.addEventListener('input', debounce(filterSessions, 300));
    }
}

/**
 * Connect to WebSocket server
 */
function connectWebSocket() {
    if (state.ws?.readyState === WebSocket.OPEN) {
        return;
    }
    
    updateConnectionStatus('connecting');
    
    try {
        state.ws = new WebSocket(CONFIG.WS_URL);
        
        state.ws.onopen = handleWebSocketOpen;
        state.ws.onmessage = handleWebSocketMessage;
        state.ws.onclose = handleWebSocketClose;
        state.ws.onerror = handleWebSocketError;
    } catch (error) {
        console.error('WebSocket connection error:', error);
        scheduleReconnect();
    }
}

/**
 * Handle WebSocket open
 */
function handleWebSocketOpen() {
    console.log('WebSocket connected');
    state.connected = true;
    state.reconnectAttempts = 0;
    updateConnectionStatus('connected');
    
    // Start heartbeat
    startHeartbeat();
    
    // Subscribe to all sessions
    sendMessage({ type: 'subscribe', session_id: null });
    
    // Request initial data
    requestSessions();
    requestStatus();
    
    showToast('Connected to dashboard', 'success');
}

/**
 * Handle WebSocket message
 */
function handleWebSocketMessage(event) {
    try {
        const message = JSON.parse(event.data);
        handleServerMessage(message);
    } catch (error) {
        console.error('Failed to parse message:', error);
    }
}

/**
 * Handle server message
 */
function handleServerMessage(message) {
    switch (message.type) {
        case 'event':
            handleEvent(message);
            break;
        case 'metrics':
            handleMetrics(message);
            break;
        case 'sessions_list':
            handleSessionsList(message.sessions);
            break;
        case 'session':
            handleSessionUpdate(message.session);
            break;
        case 'status':
            handleStatusUpdate(message);
            break;
        case 'pong':
            // Heartbeat response
            break;
        case 'error':
            console.error('Server error:', message.message);
            showToast(message.message, 'error');
            break;
        case 'subscribed':
            console.log('Subscribed to session:', message.session_id);
            break;
        default:
            console.log('Unknown message type:', message.type);
    }
}

/**
 * Handle dashboard event
 */
function handleEvent(message) {
    const event = message;
    
    switch (event.event_type) {
        case 'finding_discovered':
            handleFindingDiscovered(event);
            break;
        case 'assessment_progress':
        case 'session_progress':
            handleProgressUpdate(event);
            break;
        case 'session_created':
            handleSessionCreated(event);
            break;
        case 'session_completed':
            handleSessionCompleted(event);
            break;
        case 'session_failed':
            handleSessionFailed(event);
            break;
        case 'session_status_changed':
            handleStatusChanged(event);
            break;
        default:
            console.log('Event:', event.event_type, event);
    }
    
    // Add to activity log
    addActivity(event);
}

/**
 * Handle finding discovered
 */
function handleFindingDiscovered(event) {
    const finding = event.payload.finding;
    state.findings.unshift({ ...finding, session_id: event.session_id });
    
    // Update stats
    updateFindingStats();
    
    // Update findings table if visible
    if (state.currentView === 'findings') {
        renderFindings();
    }
    
    // Show toast for critical/high findings
    if (finding.severity === 'critical' || finding.severity === 'high') {
        showToast(
            `${finding.severity.toUpperCase()}: ${finding.title}`,
            finding.severity === 'critical' ? 'error' : 'warning'
        );
    }
}

/**
 * Handle progress update
 */
function handleProgressUpdate(event) {
    const sessionId = event.session_id;
    const session = state.sessions.get(sessionId);
    
    if (session) {
        session.progress_percent = event.payload.percent;
        session.current_phase = event.payload.phase;
        
        // Update UI
        updateSessionRow(session);
        updateStats();
    }
}

/**
 * Handle session created
 */
function handleSessionCreated(event) {
    const session = event.payload.session;
    state.sessions.set(session.assessment_id, session);
    
    updateStats();
    renderSessions();
    
    showToast(`Session created: ${session.name}`, 'success');
}

/**
 * Handle session completed
 */
function handleSessionCompleted(event) {
    const session = event.payload.session;
    state.sessions.set(session.assessment_id, session);
    
    updateStats();
    renderSessions();
    
    showToast(`Session completed: ${session.name}`, 'success');
}

/**
 * Handle session failed
 */
function handleSessionFailed(event) {
    const session = event.payload.session;
    state.sessions.set(session.assessment_id, session);
    
    updateStats();
    renderSessions();
    
    showToast(`Session failed: ${session.name}`, 'error');
}

/**
 * Handle status changed
 */
function handleStatusChanged(event) {
    const sessionId = event.session_id;
    const session = state.sessions.get(sessionId);
    
    if (session) {
        session.status = event.payload.new_status;
        updateSessionRow(session);
    }
}

/**
 * Handle metrics update
 */
function handleMetrics(message) {
    // Update metrics display if needed
    console.log('Metrics:', message);
}

/**
 * Handle sessions list
 */
function handleSessionsList(sessions) {
    state.sessions.clear();
    sessions.forEach(session => {
        state.sessions.set(session.assessment_id, session);
    });
    
    renderSessions();
    updateStats();
}

/**
 * Handle session update
 */
function handleSessionUpdate(session) {
    state.sessions.set(session.assessment_id, session);
    updateSessionRow(session);
}

/**
 * Handle status update
 */
function handleStatusUpdate(status) {
    elements.activeSessions.textContent = status.active_sessions || 0;
    elements.totalFindings.textContent = status.total_findings || 0;
}

/**
 * Handle WebSocket close
 */
function handleWebSocketClose() {
    console.log('WebSocket closed');
    state.connected = false;
    updateConnectionStatus('disconnected');
    stopHeartbeat();
    scheduleReconnect();
}

/**
 * Handle WebSocket error
 */
function handleWebSocketError(error) {
    console.error('WebSocket error:', error);
    updateConnectionStatus('disconnected');
}

/**
 * Schedule reconnection
 */
function scheduleReconnect() {
    if (state.reconnectAttempts >= CONFIG.MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached');
        showToast('Connection lost. Please refresh the page.', 'error');
        return;
    }
    
    state.reconnectAttempts++;
    console.log(`Reconnecting... (attempt ${state.reconnectAttempts})`);
    
    state.reconnectTimer = setTimeout(() => {
        connectWebSocket();
    }, CONFIG.RECONNECT_INTERVAL);
}

/**
 * Start heartbeat
 */
function startHeartbeat() {
    state.heartbeatTimer = setInterval(() => {
        if (state.connected) {
            sendMessage({ type: 'ping' });
        }
    }, CONFIG.HEARTBEAT_INTERVAL);
}

/**
 * Stop heartbeat
 */
function stopHeartbeat() {
    if (state.heartbeatTimer) {
        clearInterval(state.heartbeatTimer);
        state.heartbeatTimer = null;
    }
}

/**
 * Send message to server
 */
function sendMessage(message) {
    if (state.ws?.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify(message));
    }
}

/**
 * Request sessions from server
 */
function requestSessions() {
    sendMessage({ type: 'get_sessions' });
}

/**
 * Request status from server
 */
function requestStatus() {
    sendMessage({ type: 'get_status' });
}

/**
 * Request findings from server
 */
function requestFindings() {
    // Findings are streamed via events, but we could add a REST API call here
}

/**
 * Update connection status UI
 */
function updateConnectionStatus(status) {
    elements.connectionStatus.className = 'connection-status ' + status;
    
    const statusText = elements.connectionStatus.querySelector('.status-text');
    switch (status) {
        case 'connected':
            statusText.textContent = 'Connected';
            break;
        case 'connecting':
            statusText.textContent = 'Connecting...';
            break;
        case 'disconnected':
            statusText.textContent = 'Disconnected';
            break;
    }
}

/**
 * Update stats display
 */
function updateStats() {
    const sessions = Array.from(state.sessions.values());
    const active = sessions.filter(s => 
        s.status === 'created' || s.status === 'running'
    ).length;
    
    const totalFindings = sessions.reduce((sum, s) => sum + s.findings_count, 0);
    const critical = sessions.reduce((sum, s) => sum + s.critical_count, 0);
    const high = sessions.reduce((sum, s) => sum + s.high_count, 0);
    
    elements.activeSessions.textContent = active;
    elements.totalFindings.textContent = totalFindings;
    elements.criticalFindings.textContent = critical;
    elements.highFindings.textContent = high;
    
    updateSeverityChart(sessions);
}

/**
 * Update finding stats
 */
function updateFindingStats() {
    const total = state.findings.length;
    const critical = state.findings.filter(f => f.severity === 'critical').length;
    const high = state.findings.filter(f => f.severity === 'high').length;
    
    elements.totalFindings.textContent = total;
    elements.criticalFindings.textContent = critical;
    elements.highFindings.textContent = high;
}

/**
 * Update severity chart
 */
function updateSeverityChart(sessions) {
    const counts = {
        critical: sessions.reduce((sum, s) => sum + s.critical_count, 0),
        high: sessions.reduce((sum, s) => sum + s.high_count, 0),
        medium: 0,
        low: 0,
        info: 0,
    };
    
    const max = Math.max(...Object.values(counts), 1);
    
    Object.entries(counts).forEach(([severity, count]) => {
        const bar = elements.severityChart?.querySelector(`.severity-bar.${severity}`);
        if (bar) {
            const fill = bar.querySelector('.bar-fill');
            const percentage = (count / max) * 100;
            fill.style.width = `${Math.max(percentage, 4)}%`;
            bar.dataset.count = count;
        }
    });
}

/**
 * Render sessions table
 */
function renderSessions() {
    const sessions = Array.from(state.sessions.values());
    
    // Active sessions table
    const activeSessions = sessions.filter(s => 
        s.status === 'created' || s.status === 'running'
    );
    
    if (activeSessions.length === 0) {
        elements.sessionsTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">No active sessions</td>
            </tr>
        `;
    } else {
        elements.sessionsTableBody.innerHTML = activeSessions
            .map(session => createSessionRow(session))
            .join('');
    }
    
    // All sessions table
    if (sessions.length === 0) {
        elements.allSessionsTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="8">No sessions found</td>
            </tr>
        `;
    } else {
        elements.allSessionsTableBody.innerHTML = sessions
            .map(session => createAllSessionsRow(session))
            .join('');
    }
}

/**
 * Create session row HTML
 */
function createSessionRow(session) {
    const progress = session.progress_percent || 0;
    const statusClass = session.status.toLowerCase();
    
    return `
        <tr data-session-id="${session.assessment_id}">
            <td>${escapeHtml(session.name)}</td>
            <td>${escapeHtml(session.target_path)}</td>
            <td>${session.platform}</td>
            <td><span class="status-badge ${statusClass}">${STATUS_LABELS[session.status] || session.status}</span></td>
            <td>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${progress}%"></div>
                </div>
                <div class="progress-text">${progress}% - ${session.current_phase}</div>
            </td>
            <td>${session.findings_count}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="viewSession('${session.assessment_id}')">View</button>
            </td>
        </tr>
    `;
}

/**
 * Create all sessions row HTML
 */
function createAllSessionsRow(session) {
    const statusClass = session.status.toLowerCase();
    const created = new Date(session.created_at).toLocaleString();
    const duration = session.completed_at 
        ? formatDuration(new Date(session.completed_at) - new Date(session.created_at))
        : '-';
    
    return `
        <tr data-session-id="${session.assessment_id}">
            <td><code>${session.assessment_id.substring(0, 8)}</code></td>
            <td>${escapeHtml(session.name)}</td>
            <td>${escapeHtml(session.target_path)}</td>
            <td>${session.platform}</td>
            <td><span class="status-badge ${statusClass}">${STATUS_LABELS[session.status] || session.status}</span></td>
            <td>${created}</td>
            <td>${duration}</td>
            <td>${session.findings_count}</td>
        </tr>
    `;
}

/**
 * Update session row
 */
function updateSessionRow(session) {
    // Update in active sessions table
    const activeRow = elements.sessionsTableBody.querySelector(`[data-session-id="${session.assessment_id}"]`);
    if (activeRow) {
        activeRow.outerHTML = createSessionRow(session);
    }
    
    // Update in all sessions table
    const allRow = elements.allSessionsTableBody.querySelector(`[data-session-id="${session.assessment_id}"]`);
    if (allRow) {
        allRow.outerHTML = createAllSessionsRow(session);
    }
}

/**
 * Render findings table
 */
function renderFindings() {
    if (state.findings.length === 0) {
        elements.findingsTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6">No findings</td>
            </tr>
        `;
        return;
    }
    
    elements.findingsTableBody.innerHTML = state.findings
        .slice(0, 100) // Limit to 100 for performance
        .map(finding => createFindingRow(finding))
        .join('');
}

/**
 * Create finding row HTML
 */
function createFindingRow(finding) {
    const severity = finding.severity?.toLowerCase() || 'info';
    const location = finding.location?.file_path || '-';
    const time = new Date(finding.timestamp).toLocaleString();
    
    return `
        <tr>
            <td><span class="severity-badge ${severity}">${finding.severity}</span></td>
            <td>${escapeHtml(finding.title)}</td>
            <td>${finding.finding_type}</td>
            <td>${escapeHtml(location)}</td>
            <td><code>${finding.session_id?.substring(0, 8) || '-'}</code></td>
            <td>${time}</td>
        </tr>
    `;
}

/**
 * Add activity to log
 */
function addActivity(event) {
    const time = new Date(event.timestamp).toLocaleTimeString();
    let message = '';
    
    switch (event.event_type) {
        case 'finding_discovered':
            message = `Finding: ${event.payload.finding?.title || 'Unknown'}`;
            break;
        case 'session_created':
            message = `Session created: ${event.payload.session?.name}`;
            break;
        case 'session_completed':
            message = `Session completed: ${event.payload.session?.name}`;
            break;
        case 'session_failed':
            message = `Session failed: ${event.payload.session?.name}`;
            break;
        default:
            message = event.event_type;
    }
    
    const activity = { time, message, type: event.event_type };
    state.activities.unshift(activity);
    
    // Keep only last 50 activities
    if (state.activities.length > 50) {
        state.activities.pop();
    }
    
    renderActivities();
}

/**
 * Render activities
 */
function renderActivities() {
    if (state.activities.length === 0) {
        elements.activityList.innerHTML = `
            <div class="activity-item empty">
                <span>No recent activity</span>
            </div>
        `;
        return;
    }
    
    elements.activityList.innerHTML = state.activities
        .slice(0, 20)
        .map(activity => `
            <div class="activity-item">
                <span class="timestamp">${activity.time}</span>
                <span class="message">${escapeHtml(activity.message)}</span>
            </div>
        `)
        .join('');
}

/**
 * Filter sessions
 */
function filterSessions() {
    const statusFilter = document.getElementById('statusFilter')?.value;
    const searchTerm = document.getElementById('sessionSearch')?.value.toLowerCase();
    
    const sessions = Array.from(state.sessions.values());
    const filtered = sessions.filter(session => {
        if (statusFilter && session.status !== statusFilter) {
            return false;
        }
        if (searchTerm && !session.name.toLowerCase().includes(searchTerm) &&
            !session.target_path.toLowerCase().includes(searchTerm)) {
            return false;
        }
        return true;
    });
    
    elements.allSessionsTableBody.innerHTML = filtered
        .map(session => createAllSessionsRow(session))
        .join('');
}

/**
 * Filter findings
 */
function filterFindings() {
    const severityFilter = document.getElementById('severityFilter')?.value;
    
    let filtered = state.findings;
    if (severityFilter) {
        filtered = state.findings.filter(f => 
            f.severity?.toLowerCase() === severityFilter
        );
    }
    
    elements.findingsTableBody.innerHTML = filtered
        .slice(0, 100)
        .map(finding => createFindingRow(finding))
        .join('');
}

/**
 * View session details
 */
function viewSession(sessionId) {
    sendMessage({ type: 'get_session', session_id: sessionId });
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    elements.toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

/**
 * Load initial data
 */
async function loadInitialData() {
    try {
        // Load status
        const statusResponse = await fetch(`${CONFIG.API_URL}/status`);
        if (statusResponse.ok) {
            const status = await statusResponse.json();
            handleStatusUpdate(status);
        }
        
        // Load sessions
        const sessionsResponse = await fetch(`${CONFIG.API_URL}/sessions`);
        if (sessionsResponse.ok) {
            const data = await sessionsResponse.json();
            handleSessionsList(data.sessions);
        }
    } catch (error) {
        console.error('Failed to load initial data:', error);
    }
}

/**
 * Utility: Escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Utility: Format duration
 */
function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
    }
}

/**
 * Utility: Debounce
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (state.ws) {
        state.ws.close();
    }
    stopHeartbeat();
    if (state.reconnectTimer) {
        clearTimeout(state.reconnectTimer);
    }
});
