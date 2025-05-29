import React, { useState, useEffect } from "react";
import axios from "axios";

const API = "http://localhost:3001"; // or your deployed backend URL

function App() {
  const [view, setView] = useState("login"); // 'login' | 'register' | 'vault'
  const [form, setForm] = useState({});
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [secrets, setSecrets] = useState([]);
  const [envText, setEnvText] = useState("");

  useEffect(() => {
    if (token) fetchSecrets();
  }, [token]);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleAuth = async (endpoint) => {
    try {
      const res = await axios.post(`${API}/${endpoint}`, form);
      if (res.data.token) {
        localStorage.setItem("token", res.data.token);
        setToken(res.data.token);
        setView("vault");
      } else {
        alert("Success! Now log in.");
        setView("login");
      }
    } catch (err) {
      alert(err.response?.data || "Error");
    }
  };

  const fetchSecrets = async () => {
    try {
      const res = await axios.get(`${API}/secrets`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setSecrets(res.data);
    } catch (err) {
      alert("Auth failed or no secrets");
      setToken("");
      localStorage.removeItem("token");
      setView("login");
    }
  };

  const saveSecret = async () => {
    const label = prompt("Label?");
    const value = prompt("Secret?");
    if (!label || !value) return;

    try {
      await axios.post(
        `${API}/secret`,
        { label, value },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      fetchSecrets();
    } catch {
      alert("Failed to save");
    }
  };

  const importEnv = async () => {
    try {
      await axios.post(
        `${API}/import-env`,
        { envText },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setEnvText("");
      fetchSecrets();
    } catch {
      alert("Import failed");
    }
  };

  const logout = () => {
    localStorage.removeItem("token");
    setToken("");
    setView("login");
  };

  return (
    <div style={{ fontFamily: "Arial", padding: 20, maxWidth: 600, margin: "auto" }}>
      <h2>🔐 DevVault</h2>

      {view === "login" || view === "register" ? (
        <div>
          <h3>{view === "login" ? "Login" : "Register"}</h3>
          <input placeholder="Username" name="username" onChange={handleChange} /><br />
          <input placeholder="Password" name="password" type="password" onChange={handleChange} /><br />
          <button onClick={() => handleAuth(view)}>{view}</button>
          <p>
            {view === "login" ? (
              <span onClick={() => setView("register")}>Don't have an account? Register</span>
            ) : (
              <span onClick={() => setView("login")}>Already have an account? Login</span>
            )}
          </p>
        </div>
      ) : (
        <div>
          <p>
            Welcome to your secure vault. <button onClick={logout}>Logout</button>
          </p>
          <button onClick={saveSecret}>➕ Add Secret</button>

          <h4>Stored Secrets</h4>
          <ul>
            {secrets.map((s, i) => (
              <li key={i}>
                <b>{s.label}</b>: {s.value}
              </li>
            ))}
          </ul>

          <h4>Import from .env</h4>
          <textarea
            value={envText}
            onChange={(e) => setEnvText(e.target.value)}
            rows={5}
            cols={50}
            placeholder="API_KEY=abc123\nSECRET_KEY=xyz456"
          />
          <br />
          <button onClick={importEnv}>📤 Import .env</button>
        </div>
      )}
    </div>
  );
}

export default App;
