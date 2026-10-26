import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, auth } from "../api";

// Login / register gate. On success the JWT is stored and onAuthed() flips the
// app into the dashboard. Register and login share one form; a toggle picks the
// endpoint. Password rules mirror the backend (min 8 chars) to fail fast.
export function AuthGate({ onAuthed }: { onAuthed: () => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const submit = useMutation({
    mutationFn: () =>
      mode === "login"
        ? api.login(username, password)
        : api.register(username, password),
    onSuccess: (res) => {
      auth.setToken(res.access_token);
      onAuthed();
    },
  });

  const canSubmit = username.trim().length >= 3 && password.length >= 8;

  return (
    <div className="max-w-sm mx-auto mt-24 p-6 border border-slate-800 rounded bg-slate-900">
      <h1 className="text-2xl font-bold mb-1">SecureLens</h1>
      <p className="text-slate-400 mb-6 text-sm">AI-augmented DevSecOps triage</p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) submit.mutate();
        }}
        className="space-y-3"
      >
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full bg-slate-800 px-3 py-2 rounded text-sm"
          placeholder="username (min 3 chars)"
          autoComplete="username"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full bg-slate-800 px-3 py-2 rounded text-sm"
          placeholder="password (min 8 chars)"
          autoComplete={mode === "login" ? "current-password" : "new-password"}
        />
        <button
          type="submit"
          disabled={!canSubmit || submit.isPending}
          className="w-full px-3 py-2 rounded bg-emerald-600 text-sm font-semibold disabled:opacity-50"
        >
          {submit.isPending
            ? "Please wait…"
            : mode === "login"
            ? "Sign in"
            : "Create account"}
        </button>
      </form>

      {submit.isError && (
        <p className="text-xs text-red-400 mt-3">
          {mode === "login"
            ? "Sign-in failed. Check your username and password."
            : "Could not register. That username may be taken."}
        </p>
      )}

      <button
        onClick={() => {
          setMode(mode === "login" ? "register" : "login");
          submit.reset();
        }}
        className="text-xs text-indigo-400 mt-4 hover:underline"
      >
        {mode === "login"
          ? "Need an account? Register"
          : "Have an account? Sign in"}
      </button>
    </div>
  );
}
