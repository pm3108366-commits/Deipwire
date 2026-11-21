const express = require('express');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const keys = {};

app.post('/api/genkey', (req, res) => {
  const key = uuidv4().replace(/-/g, '').substring(0, 16).toUpperCase();
  const dias = req.body.dias || 7;
  const expira = Date.now() + dias * 24 * 60 * 60 * 1000;
  keys[key] = { expira, ativo: true };
  res.json({ key, expira });
});

app.post('/api/validar', (req, res) => {
  const { key } = req.body;
  if (!keys[key]) return res.json({ valido: false, motivo: 'Key inválida' });
  if (Date.now() > keys[key].expira) return res.json({ valido: false, motivo: 'Key expirada' });
  res.json({ valido: true, expira: keys[key].expira });
});

app.post('/api/config', (req, res) => {
  const { key, ibot, esp, antiban } = req.body;
  if (!keys[key]) return res.status(403).json({ erro: 'Key inválida' });
  if (Date.now() > keys[key].expira) return res.status(403).json({ erro: 'Key expirada' });

  const config = {
    log: { loglevel: "none" },
    inbounds: [{ port: 10808, protocol: "socks", settings: { auth: "noauth", udp: true } }],
    outbounds: [
      { protocol: "freedom", settings: {}, tag: "direct" },
      { protocol: "blackhole", settings: {}, tag: "block" }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: buildRules(ibot, esp, antiban)
    },
    tripwire: { ibot: !!ibot, esp: !!esp, antiban: !!antiban, versao: "1.0.0" }
  };

  res.setHeader('Content-Disposition', 'attachment; filename="tripwire.json"');
  res.setHeader('Content-Type', 'application/json');
  res.json(config);
});

function buildRules(ibot, esp, antiban) {
  const rules = [];
  if (antiban) {
    rules.push({
      type: "field",
      domain: ["domain:garena.com", "domain:garena.io", "keyword:anticheat", "keyword:detection"],
      outboundTag: "block"
    });
  }
  rules.push({ type: "field", network: "tcp,udp", outboundTag: "direct" });
  return rules;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Tripwire rodando na porta ${PORT}`));
