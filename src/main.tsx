import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// Show render errors in the window instead of a black screen (helps debug Electron)
class RootErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
    state = { error: null as Error | null }
    static getDerivedStateFromError(error: Error) {
        return { error }
    }
    componentDidCatch(error: Error, info: React.ErrorInfo) {
        console.error('[Root] Render error:', error, info.componentStack)
    }
    render() {
        if (this.state.error) {
            return (
                <div style={{
                    padding: 24,
                    color: '#fca5a5',
                    backgroundColor: '#171717',
                    fontFamily: 'system-ui, sans-serif',
                    minHeight: '100vh',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                }}>
                    <h2 style={{ color: '#f87171', marginBottom: 8 }}>STRIX – Render error</h2>
                    <pre style={{ margin: 0 }}>{this.state.error.message}</pre>
                    <pre style={{ marginTop: 12, fontSize: 12, color: '#94a3b8' }}>{this.state.error.stack}</pre>
                </div>
            )
        }
        return this.props.children
    }
}

// Log unhandled errors so they appear in Electron DevTools / console
if (typeof window !== 'undefined') {
    window.onerror = (message, source, lineno, colno, error) => {
        console.error('[Unhandled error]', message, source, lineno, colno, error)
    }
    window.onunhandledrejection = (e) => {
        console.error('[Unhandled rejection]', e.reason)
    }
}

const root = document.getElementById('root')
if (!root) throw new Error('Root element #root not found')
// Remove loading placeholder so React mounts into empty root (avoids flash in browser)
const loadingEl = document.getElementById('root-loading')
if (loadingEl) loadingEl.remove()

ReactDOM.createRoot(root).render(
    <React.StrictMode>
        <RootErrorBoundary>
            <App />
        </RootErrorBoundary>
    </React.StrictMode>,
)
