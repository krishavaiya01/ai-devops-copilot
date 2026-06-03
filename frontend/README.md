# AI DevOps Copilot - Frontend React Client

The frontend client of the **AI DevOps Copilot** platform is a premium, responsive Single Page Application (SPA) designed to provide SREs and Cloud Engineers with a command-center interface to monitor and analyze infrastructure.

---

## 🛠️ Tech Stack & Features

- **Core Framework**: React 19 & TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Visualization & Graphs**: Recharts (for real-time Grafana-style CPU, memory, latency, and error widgets)
- **Icons**: Lucide Icons
- **HTTP Client**: Axios (configured with interceptors to automatically forward JWT authentication tokens)
- **State Management**: React Context API (`AuthContext`) tracking session login, token payloads, and active user roles (`admin` / `engineer`)

---

## 📂 Project Structure

```text
frontend/
├── public/               # Static assets
├── src/
│   ├── components/       # Layout, Navigation Sidebar, ProtectedRoute wrappers
│   ├── context/          # JWT Auth Context state & handlers
│   ├── pages/            # View pages:
│   │   ├── Dashboard.tsx          # Real-time infrastructure charts
│   │   ├── LogAnalyzer.tsx        # Log paste, analysis, and AI suggestion console
│   │   ├── IncidentCenter.tsx     # Active outages list, creation forms, timelines
│   │   ├── CostOptimization.tsx   # AWS capacity/spend saving guidelines
│   │   ├── AIChat.tsx             # Interactive stateful SRE AI helper
│   │   ├── Settings.tsx           # Setup credentials and config adjustments
│   │   └── Login.tsx              # Platform login credentials entry
│   ├── services/         # Axios API connection endpoints
│   ├── App.tsx           # Router layout and private route mappings
│   ├── main.tsx          # React application entrypoint
│   └── index.css         # Tailwind directives & global styling base
├── Dockerfile            # Production NGINX web server image builder
├── package.json          # Node dependency scripts
├── tsconfig.json         # TypeScript configuration
└── tailwind.config.js    # Tailwind layout utility configurations
```

---

## 🚀 Setup & Local Execution

### 1. Prerequisites
- Node.js 20+
- A running Backend API server (by default expected at `http://localhost:8000`)

### 2. Install Dependencies
```powershell
npm install
```

### 3. Running the Client
Start the Vite development hot-reloading server:
```powershell
npm run dev
```
*The React client will be available at [http://localhost:5173](http://localhost:5173).*

---

## 🏗️ Production Build & Verification

### 1. Type Check & Compile Production Assets
Ensure TypeScript compiles successfully and builds output chunks to the `/dist` folder:
```powershell
npm run build
```

### 2. Linting (ESLint)
Verify there are no syntax or style guidelines issues:
```powershell
npm run lint
```
