
import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import webpush from "web-push";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/bomberos";
await mongoose.connect(MONGO_URI);

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  station: String,
  role: { type: String, enum: ["jefe","operador","voluntario"], default: "voluntario" },
  passwordHash: String,
  pushSubs: { type: Array, default: [] }
});

const messageSchema = new mongoose.Schema({
  room: String,
  text: String,
  priority: { type: String, enum: ["INFO","URGENTE","EVAC"], default: "INFO" },
  ts: { type: Date, default: Date.now },
  user: { id: String, name: String, station: String, role: String },
  location: { lat: Number, lng: Number }
});

const roomSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  allowedRoles: { type: [String], default: ["jefe","operador","voluntario"] },
  station: { type: String, default: "*" }
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);
const Room = mongoose.model("Room", roomSchema);

// Seed rooms
if (await Room.countDocuments() === 0) {
  await Room.create([
    { name: "alertas", allowedRoles: ["jefe","operador","voluntario"] },
    { name: "operaciones", allowedRoles: ["jefe","operador"] },
    { name: "logística", allowedRoles: ["jefe","operador"] }
  ]);
}

// Auth utils
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
function signToken(user){
  return jwt.sign({ sub: user._id.toString(), role: user.role, name: user.name, station: user.station }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req,res,next){
  const h=req.headers.authorization; if(!h) return res.status(401).json({error:"no token"});
  try{ req.user=jwt.verify(h.split(" ")[1], JWT_SECRET); next(); }catch{ res.status(401).json({error:"invalid token"}); }
}
function authOptional(req,res,next){
  const h=req.headers.authorization; if(h){ try{ req.user = jwt.verify(h.split(" ")[1], JWT_SECRET); }catch{} } next();
}

// Web Push
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || "";
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || "";
if (VAPID_PUBLIC && VAPID_PRIVATE) webpush.setVapidDetails("mailto:admin@example.com", VAPID_PUBLIC, VAPID_PRIVATE);

// API
app.post("/api/auth/register", async (req,res)=>{
  const { name, email, password, station="Estación 1", role="voluntario" } = req.body;
  const exists = await User.findOne({ email }); if(exists) return res.status(409).json({ error:"email en uso" });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, station, role, passwordHash });
  res.json({ ok:true, user: { id:user._id, name:user.name, station:user.station, role:user.role, email:user.email } });
});

app.post("/api/auth/login", async (req,res)=>{
  const { email, password } = req.body;
  const user = await User.findOne({ email }); if(!user) return res.status(401).json({ error:"invalid" });
  const ok = await bcrypt.compare(password, user.passwordHash); if(!ok) return res.status(401).json({ error:"invalid" });
  const token = signToken(user);
  res.json({ token, user: { id:user._id, name:user.name, station:user.station, role:user.role, email:user.email } });
});

app.get("/api/auth/me", auth, async (req,res)=>{
  const user = await User.findById(req.user.sub);
  if(!user) return res.status(404).json({}); res.json({ user: { id:user._id, name:user.name, station:user.station, role:user.role, email:user.email } });
});

app.get("/api/rooms", authOptional, async (req,res)=>{
  const role = req.user?.role || "voluntario";
  const rooms = await Room.find({ allowedRoles: role });
  res.json({ rooms: rooms.map(r=>r.name) });
});

app.get("/api/messages", auth, async (req,res)=>{
  const { room="alertas", limit=100 } = req.query;
  if (!(await canAccessRoom(req.user.role, room))) return res.status(403).json({ error:"forbidden" });
  const msgs = await Message.find({ room }).sort({ ts: 1 }).limit(Math.min(Number(limit), 500));
  res.json({ messages: msgs });
});

app.post("/api/messages", auth, async (req,res)=>{
  const { room, text="", priority="INFO", location } = req.body;
  if(!room) return res.status(400).json({ error:"room required" });
  if (!(await canAccessRoom(req.user.role, room))) return res.status(403).json({ error:"forbidden" });
  const user = await User.findById(req.user.sub);
  const msg = await Message.create({ room, text, priority, location, user: { id:user._id.toString(), name:user.name, station:user.station, role:user.role }, ts:new Date() });
  io.to(room).emit("message", msg);
  if (priority!=="INFO" && VAPID_PUBLIC && VAPID_PRIVATE) {
    // naive broadcast to all subscribers
    const users = await User.find({ pushSubs: { $exists:true, $ne: [] } }, { pushSubs:1, name:1 });
    for (const u of users) {
      for (const sub of u.pushSubs) {
        try { await webpush.sendNotification(sub, JSON.stringify({ title:`🚨 ${room} • ${priority}`, body:`${msg.user.name}: ${msg.text}`, tag: msg._id.toString() })); } catch(e){}
      }
    }
  }
  res.json({ ok:true });
});

app.get("/api/push/public-key", (req,res)=> res.json({ publicKey: VAPID_PUBLIC }));
app.post("/api/push/subscribe", auth, async (req,res)=>{
  const user = await User.findById(req.user.sub); if(!user) return res.status(404).json({});
  if(!user.pushSubs.find(s=> s.endpoint === req.body.endpoint)){ user.pushSubs.push(req.body); await user.save(); }
  res.json({ ok:true });
});

async function canAccessRoom(role, roomName){ const room = await Room.findOne({ name: roomName }); return room ? room.allowedRoles.includes(role) : false; }

// Server & sockets
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods:["GET","POST"] } });

io.use((socket, next)=>{
  const token = socket.handshake.auth?.token; if(!token) return next(new Error("no token"));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); } catch { next(new Error("invalid token")); }
});

io.on("connection", (socket)=>{
  const role = socket.user.role;
  Room.find({ allowedRoles: role }).then(rooms => { const def = rooms[0]?.name || "alertas"; socket.join(def); });
  socket.on("join", async ({ room })=>{
    if(await canAccessRoom(socket.user.role, room)){ for(const r of socket.rooms){ if(r!==socket.id) socket.leave(r); } socket.join(room); }
  });
  socket.on("location", (payload)=> io.emit("location", { user:{ id:socket.user.sub, name:socket.user.name }, location: payload.location }));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>{
  console.log(`Servidor listo en http://localhost:${PORT}`);
  if(!VAPID_PUBLIC || !VAPID_PRIVATE){ console.log("ℹ️ Web Push opcional: configura VAPID_PUBLIC/VAPID_PRIVATE para activar notificaciones push."); }
});
