// nfse-bridge — serviço mínimo que faz chamadas mTLS ao ADN (Sistema Nacional NFS-e).
// Não armazena certificados: recebe o .pfx por requisição (via HTTPS, autenticado por token),
// usa-o em memória e o descarta. Nunca registra certificado, senha ou corpo da requisição.
import http from "node:http";
import { Agent, request } from "undici";

const PORT = Number(process.env.PORT ?? 8080);
const TOKEN = process.env.BRIDGE_TOKEN;
if (!TOKEN || TOKEN.length < 32) throw new Error("Defina BRIDGE_TOKEN (>= 32 caracteres).");

// URLs oficiais: https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/apis-prod-restrita-e-producao
const HOSTS = {
  homologacao: { adn: "https://adn.producaorestrita.nfse.gov.br/contribuintes", danfse: "https://adn.producaorestrita.nfse.gov.br/danfse" },
  producao: { adn: "https://adn.nfse.gov.br/contribuintes", danfse: "https://adn.nfse.gov.br/danfse" },
};
// Parâmetros de consulta opcionais — confira os nomes no Swagger oficial (/contribuintes/docs) antes de ativar.
const DFE_QUERY = process.env.ADN_DFE_QUERY ?? ""; // ex.: "lote=true"
const CNPJ_PARAM = process.env.ADN_CNPJ_CONSULTA_PARAM ?? ""; // nome do parâmetro de CNPJ de consulta, se usado

function agentFor({ pfx_base64, password }) {
  return new Agent({ connect: { pfx: Buffer.from(pfx_base64, "base64"), passphrase: password, timeout: 20_000 } });
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) { size += c.length; if (size > 2_000_000) throw new Error("payload grande demais"); chunks.push(c); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function send(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true });
    if (req.method !== "POST") return send(res, 405, { error: "method" });
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(res, 401, { error: "unauthorized" });
    const body = await readJson(req);
    const hosts = HOSTS[body.environment];
    if (!hosts) return send(res, 400, { error: "environment inválido" });
    const dispatcher = agentFor(body);
    try {
      if (req.url === "/adn/dfe") {
        const nsu = Math.max(0, Number(body.nsu) | 0);
        const qs = new URLSearchParams(DFE_QUERY);
        if (CNPJ_PARAM && body.cnpj_consulta) qs.set(CNPJ_PARAM, String(body.cnpj_consulta));
        const url = `${hosts.adn}/DFe/${nsu}${qs.toString() ? "?" + qs : ""}`;
        const r = await request(url, { method: "GET", dispatcher, headers: { accept: "application/json" } });
        const text = await r.body.text();
        let json = null; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 2000) }; }
        return send(res, 200, { status: r.statusCode, body: json });
      }
      if (req.url === "/adn/danfse") {
        const chave = String(body.chave ?? "").replace(/\D/g, "");
        if (chave.length < 40) return send(res, 400, { error: "chave inválida" });
        const r = await request(`${hosts.danfse}/${chave}`, { method: "GET", dispatcher, headers: { accept: "application/pdf" } });
        const buf = Buffer.from(await r.body.arrayBuffer());
        const ct = r.headers["content-type"] ?? null;
        if (r.statusCode === 200 && String(ct).includes("pdf")) return send(res, 200, { status: 200, content_type: ct, body_base64: buf.toString("base64") });
        return send(res, 200, { status: r.statusCode, content_type: ct, body_base64: null, error: `DANFSe indisponível (HTTP ${r.statusCode}) ${buf.toString("utf8").slice(0, 300)}` });
      }
      return send(res, 404, { error: "rota" });
    } finally {
      await dispatcher.close();
    }
  } catch (e) {
    const msg = String(e?.code ?? e?.message ?? e);
    const friendly = /mac verify|password|PKCS12/i.test(msg) ? "Falha ao abrir o certificado (senha/arquivo)." : `Falha de conexão: ${msg}`;
    return send(res, 502, { error: friendly });
  }
});

server.listen(PORT, () => console.log(`nfse-bridge ouvindo na porta ${PORT}`));
