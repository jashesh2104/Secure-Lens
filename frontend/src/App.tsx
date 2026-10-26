import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { auth } from "./api";
import { AuthGate } from "./components/AuthGate";
import { Dashboard } from "./components/Dashboard";

export default function App() {
  const qc = useQueryClient();
  const [authed, setAuthed] = useState(auth.isAuthed());

  // A 401 from any request clears the token and emits this event; drop to login.
  useEffect(() => {
    const onUnauthorized = () => setAuthed(false);
    window.addEventListener("securelens:unauthorized", onUnauthorized);
    return () =>
      window.removeEventListener("securelens:unauthorized", onUnauthorized);
  }, []);

  if (!authed) {
    return <AuthGate onAuthed={() => setAuthed(true)} />;
  }

  return (
    <Dashboard
      onLogout={() => {
        auth.clear();
        qc.clear(); // drop cached findings/scan so the next user starts clean
        setAuthed(false);
      }}
    />
  );
}

