// nfse-bridge — serviço mínimo que faz chamadas mTLS ao ADN (Sistema Nacional NFS-e).
// Não armazena certificados: recebe o .pfx por requisição (via HTTPS, autenticado por token),
// usa-o em memória e o descarta. Nunca registra certificado, senha ou corpo da requisição.
import http from "node:http";
import crypto from "node:crypto";
import { Agent, request } from "undici";
import forge from "node-forge";
import { sefazDistribution } from "./sefaz.mjs";
import { adnManifest, sefazEvent } from "./manifest.mjs";

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

// Muitos .pfx A1 usam criptografia antiga (RC2-40 / 3DES) que o OpenSSL 3 do Node recusa com
// ERR_CRYPTO_UNSUPPORTED_OPERATION. Extraímos chave e certificado com node-forge, que entende
// esses formatos, e entregamos PEM ao TLS. Se algo der errado, usamos o .pfx como está.
function tlsOptions(pfx, password) {
  try {
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfx.toString("binary")), password);
    let key = null;
    const certs = [];
    for (const safe of p12.safeContents) {
      for (const bag of safe.safeBags) {
        if (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) key = bag.key;
        if (bag.type === forge.pki.oids.certBag && bag.cert) certs.push(forge.pki.certificateToPem(bag.cert));
      }
    }
    if (key && certs.length) {
      const keyPem = forge.pki.privateKeyToPem(key);
      const certPem = certs.join("");
      crypto.createPrivateKey(keyPem);
      new crypto.X509Certificate(certPem);
      return { cert: certPem, key: keyPem };
    }
  } catch {
    // segue usando o .pfx original
  }
  return { pfx, passphrase: password };
}

function agentFor({ pfx_base64, password }) {
  return new Agent({ connect: { ...tlsOptions(Buffer.from(pfx_base64, "base64"), password), timeout: 20_000 } });
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
      if (req.url === "/sefaz/dfe") return send(res, 200, await sefazDistribution(body, dispatcher));
      if (req.url === "/sefaz/evento") return send(res, 200, await sefazEvent(body, dispatcher, Buffer.from(body.pfx_base64, "base64"), body.password));
      if (req.url === "/adn/manifest") return send(res, 200, await adnManifest(body, dispatcher, hosts, Buffer.from(body.pfx_base64, "base64"), body.password));
      if (req.url === "/adn/dfe") {
        const nsu = Math.max(0, Number(body.nsu));
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
