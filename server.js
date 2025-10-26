// server.js
import 'dotenv/config';
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🔐 Config Supabase (les clés sont dans Render)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// 🔑 Secret JWT (à garder dans Render aussi)
const SECRET = process.env.JWT_SECRET || "tivim-secret-key";

// --- Routes ---

// ✅ Test route
app.get("/", (req, res) => {
  res.send({ status: "ok", message: "Tivi-M API connected to Supabase 🚀" });
});

// 🔐 Register
app.post("/auth/register", async (req, res) => {
  const { email, password, name } = req.body;

  // Vérifie si utilisateur existe déjà
  const { data: existing } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .maybeSingle();

  if (existing) {
    return res.status(400).send({ message: "Email déjà utilisé" });
  }

  // Hash du mot de passe
  const hashed = bcrypt.hashSync(password, 8);

  // Insertion dans Supabase
  const { data, error } = await supabase
    .from("users")
    .insert([{ email, password: hashed, name }])
    .select()
    .single();

  if (error) return res.status(500).send({ message: error.message });

  const token = jwt.sign({ id: data.id }, SECRET, { expiresIn: "7d" });
  res.status(201).send({ token, user: { id: data.id, email, name } });
});

// 🔓 Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .maybeSingle();

  if (error) return res.status(500).send({ message: error.message });
  if (!user) return res.status(404).send({ message: "Utilisateur non trouvé" });

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.status(401).send({ message: "Mot de passe incorrect" });

  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "7d" });
  res.send({ token, user: { id: user.id, email: user.email, name: user.name } });
});

// ✅ Exemple : lire les chaînes (dans Supabase ou mock)
app.get("/channels", async (req, res) => {
  const { data, error } = await supabase.from("channels").select("*");
  if (error) return res.status(500).send({ message: error.message });
  res.send(data);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ API Tivi-M (Supabase) running on port ${PORT}`));
