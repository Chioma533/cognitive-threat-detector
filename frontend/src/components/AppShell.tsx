import type { ReactNode } from "react";

interface AppShellProps {
  children: ReactNode;
  connectionStatus: "checking" | "online" | "offline";
  onCheckConnection: () => void;
}

const navigation = [
  { href: "#overview", label: "Overview", number: "01" },
  { href: "#upload", label: "Dataset assessment", number: "02" },
  { href: "#results", label: "Assessment results", number: "03" },
];

export default function AppShell({
  children,
  connectionStatus,
  onCheckConnection,
}: AppShellProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="Cognitive Threat Detection home">
          <span className="brand-mark" aria-hidden="true">
            CT
          </span>
          <span className="brand-copy">
            <strong>Cognitive</strong>
            <span>THREAT DETECTION</span>
          </span>
        </a>

        <div className="sidebar-section-label">Workspace</div>
        <nav className="side-nav" aria-label="Main navigation">
          {navigation.map((item, index) => (
            <a
              className={`side-nav-link${index === 0 ? " active" : ""}`}
              href={item.href}
              key={item.href}
            >
              <span className="nav-number">{item.number}</span>
              {item.label}
              {index === 0 && <span className="nav-indicator" />}
            </a>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-card">
            <span className="system-orbit" aria-hidden="true" />
            <span className="system-card-title">Assessment engine</span>
            <span className="system-card-copy">
              Machine learning and rule-based evidence
            </span>
          </div>
          <div className="sidebar-version">
            <span className="version-dot" />
            Prototype workspace
          </div>
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="breadcrumb-divider">/</span>
            <strong>Dashboard</strong>
          </div>
          <button
            className="connection-control"
            onClick={onCheckConnection}
            type="button"
            aria-label="Check backend connection"
          >
            <span
              className={`connection-dot ${connectionStatus}`}
              aria-hidden="true"
            />
            <span>
              {connectionStatus === "checking"
                ? "Checking backend"
                : connectionStatus === "online"
                  ? "Backend connected"
                  : "Backend offline"}
            </span>
            <span className="refresh-glyph" aria-hidden="true">
              ↻
            </span>
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}
