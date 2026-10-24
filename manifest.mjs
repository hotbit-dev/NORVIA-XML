// Envio de eventos de manifestação do destinatário: NF-e/CT-e via SOAP SEFAZ, NFS-e via ADN.
// Os eventos são assinados (XMLDSig RSA-SHA1) com a chave extraída do .pfx via node-forge.
import zlib from "node:zlib";
import { request } from "undici";
import { XMLParser } from "fast-xml-parser";
import forge from "node-forge";

const EVENT_SERVICES = {
  nfe: { producao: "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx", homologacao: "https://hom1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx", ns: "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4", op: "nfeRecepcaoEvento", dados: "nfeDadosMsg" },
  cte: { producao: "https://www1.cte.fazenda.gov.br/CTeRecepcaoEventoV4/CTeRecepcaoEventoV4.asmx", homologacao: "https://hom1.cte.fazenda.gov.br/CTeRecepcaoEventoV4/CTeRecepcaoEventoV4.asmx", ns: "http://www.portalfiscal.inf.br/cte/wsdl/CTeRecepcaoEventoV4", op: "cteRecepcaoEvento", dados: "cteDadosMsg" },
};

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", removeNSPrefix: true, parseTagValue: false, processEntities: false });
const escapeXml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function extractKeyCert(pfxBuffer, password) {
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxBuffer.toString("binary")), password);
  let key = null;
  let cert = null;
  for (const safe of p12.safeContents) {
    for (const bag of safe.safeBags) {
      if ((bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) && !key) key = bag.key;
      if (bag.type === forge.pki.oids.certBag && bag.cert && !cert) cert = bag.cert;
    }
  }
  if (!key || !cert) throw new Error("Não foi possível extrair chave e certificado do arquivo para assinar o evento.");
  return { key, certDerB64: forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()) };
}

const sha1B64 = (str) => { const md = forge.md.sha1.create(); md.update(str, "utf8"); return forge.util.encode64(md.digest().bytes()); };

function signInfEvento(key, certDerB64, infXml, id) {
  const digest = sha1B64(infXml);
  const signedInfo = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#${id}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>${digest}</DigestValue></Reference></SignedInfo>`;
  const md = forge.md.sha1.create();
  md.update(signedInfo, "utf8");
  const sig = forge.util.encode64(key.sign(md));
  return `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<SignatureValue>${sig}</SignatureValue><KeyInfo><X509Data><X509Certificate>${certDerB64}</X509Certificate></X509Data></KeyInfo></Signature>`;
}

const dhEvento = () => new Date().toLocaleString("sv-SE", { timeZone: "America/Sao_Paulo" }).replace(" ", "T") + "-03:00";

function buildEvento(source, body) {
  const { environment, cnpj, chave, code, descricao, justificativa } = body;
  const id = `ID${code}${chave}01`;
  const tpAmb = environment === "producao" ? 1 : 2;
  const just = justificativa ? `<xJust>${escapeXml(justificativa)}</xJust>` : "";
  if (source === "nfe") {
    const det = `<detEvento versao="1.00"><descEvento>${escapeXml(descricao)}</descEvento>${just}</detEvento>`;
    const inf = `<infEvento Id="${id}"><cOrgao>91</cOrgao><tpAmb>${tpAmb}</tpAmb><CNPJ>${cnpj}</CNPJ><chNFe>${chave}</chNFe><dhEvento>${dhEvento()}</dhEvento><tpEvento>${code}</tpEvento><nSeqEvento>1</nSeqEvento><verEvento>1.00</verEvento>${det}</infEvento>`;
    return { id, inf, wrap: (sig) => `<envEvento versao="1.00" xmlns="http://www.portalfiscal.inf.br/nfe"><idLote>1</idLote><evento versao="1.00">${inf}${sig}</evento></envEvento>` };
  }
  const det = `<detEvento versao="4.00"><evPrestDesacordo><descEvento>${escapeXml(descricao)}</descEvento><indDesacordoOper>1</indDesacordoOper><xObs>${escapeXml(justificativa ?? "")}</xObs></evPrestDesacordo></detEvento>`;
  const inf = `<infEvento Id="${id}"><cOrgao>${body.uf_code ?? "91"}</cOrgao><tpAmb>${tpAmb}</tpAmb><CNPJ>${cnpj}</CNPJ><chCTe>${chave}</chCTe><dhEvento>${dhEvento()}</dhEvento><tpEvento>${code}</tpEvento><nSeqEvento>1</nSeqEvento><verEvento>4.00</verEvento>${det}</infEvento>`;
  return { id, inf, wrap: (sig) => `<envEventoCTe versao="4.00" xmlns="http://www.portalfiscal.inf.br/cte"><idLote>1</idLote><eventoCTe versao="4.00">${inf}${sig}</eventoCTe></envEventoCTe>` };
}

function findNode(value, name) {
  if (!value || typeof value !== "object") return null;
  if (value[name]) return value[name];
  for (const item of Object.values(value)) {
    if (typeof item === "string" && item.includes(`<${name}`)) { const found = findNode(parser.parse(item), name); if (found) return found; }
    const found = findNode(item, name);
    if (found) return found;
  }
  return null;
}

export function parseEventResponse(xml) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("Resposta XML SEFAZ inválida.");
  const ret = findNode(parser.parse(xml), "retEnvEvento");
  if (!ret) throw new Error("Resposta inesperada do serviço de eventos SEFAZ.");
  const inf = ret.infEvento ?? {};
  return {
    code: String(ret.cStat ?? ""),
    message: String(ret.xMotivo ?? ""),
    event_code: String(inf.cStat ?? ""),
    event_message: String(inf.xMotivo ?? ""),
    protocol: inf.nProt ? String(inf.nProt) : null,
  };
}

export async function sefazEvent(body, dispatcher, pfxBuffer, password) {
  const service = EVENT_SERVICES[body.source];
  if (!service || !["producao", "homologacao"].includes(body.environment)) throw new Error("Serviço de evento SEFAZ inválido.");
  if (!/^\d{14}$/.test(String(body.cnpj ?? "")) || !/^\d{44}$/.test(String(body.chave ?? ""))) throw new Error("CNPJ ou chave inválidos para o evento.");
  const { key, certDerB64 } = extractKeyCert(pfxBuffer, password);
  const { id, inf, wrap } = buildEvento(body.source, body);
  const signed = wrap(signInfEvento(key, certDerB64, inf, id));
  const envelope = `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><${service.op} xmlns="${service.ns}"><${service.dados}>${signed}</${service.dados}></${service.op}></soap12:Body></soap12:Envelope>`;
  const response = await request(service[body.environment], { method: "POST", dispatcher, headersTimeout: 30000, bodyTimeout: 30000, headers: { "content-type": `application/soap+xml; charset=utf-8; action="${service.ns}/${service.op}"`, accept: "application/soap+xml" }, body: envelope });
  const raw = await response.body.text();
  if (response.statusCode !== 200) throw new Error(`SEFAZ indisponível (HTTP ${response.statusCode}).`);
  const r = parseEventResponse(raw);
  const ok = r.code === "135" || r.code === "136" || r.event_code === "135" || r.event_code === "136";
  return { ok, code: r.event_code || r.code, message: r.event_message || r.message, protocol: r.protocol };
}

const SEFIN = {
  homologacao: "https://sefin.producaorestrita.nfse.gov.br/SefinNacional",
  producao: "https://sefin.nfse.gov.br/SefinNacional",
};

function describeError(json, text, status, url) {
  const e = Array.isArray(json?.erros) ? json.erros[0] : Array.isArray(json?.Erros) ? json.Erros[0] : null;
  const detail = e ? [e.Codigo ?? e.codigo, e.Descricao ?? e.descricao, e.Complemento ?? e.complemento].filter(Boolean).join(" — ") : (json?.mensagem ?? json?.message ?? json?.title ?? String(text ?? "").trim().slice(0, 300));
  return `Portal Nacional respondeu HTTP ${status}${detail ? `: ${detail}` : " sem detalhes"} (${url.replace(/\/nfse\/[^/]+\//, "/nfse/{chave}/")})`;
}

export async function adnManifest(body, dispatcher, hosts, pfxBuffer, password) {
  const chave = String(body.chave ?? "").replace(/\D/g, "");
  if (!/^\d{14}$/.test(String(body.cnpj ?? "")) || !chave) throw new Error("CNPJ ou chave inválidos para o evento.");
  const env = body.environment === "producao" ? "producao" : "homologacao";
  const { key, certDerB64 } = extractKeyCert(pfxBuffer, password);
  const id = `PRE${chave}${body.code}001`;
  const inf = `<infPedReg Id="${id}"><tpAmb>${env === "producao" ? 1 : 2}</tpAmb><verAplic>PainelFiscal-1.0</verAplic><dhEvento>${dhEvento()}</dhEvento><CNPJAutor>${body.cnpj}</CNPJAutor><chNFSe>${chave}</chNFSe><nPedRegEvento>1</nPedRegEvento><e${body.code}><xDesc>${escapeXml(body.descricao ?? "Manifestacao do Tomador")}</xDesc>${body.justificativa ? `<xMotivo>${escapeXml(body.justificativa)}</xMotivo>` : ""}</e${body.code}></infPedReg>`;
  const signed = `<?xml version="1.0" encoding="UTF-8"?><pedRegEvento versao="1.00" xmlns="http://www.sped.fazenda.gov.br/nfse">${inf}${signInfEvento(key, certDerB64, inf, id)}</pedRegEvento>`;
  const gz = zlib.gzipSync(Buffer.from(signed, "utf8")).toString("base64");
  const custom = process.env.ADN_MANIFEST_URL ?? "";
  const url = custom ? custom.replace("{chave}", chave) : `${SEFIN[env]}/nfse/${chave}/eventos`;
  let r;
  try {
    r = await request(url, { method: "POST", dispatcher, headersTimeout: 30000, bodyTimeout: 30000, headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ pedidoRegistroEventoXmlGZipB64: gz }) });
  } catch (e) {
    return { ok: false, code: "conexao", message: `Sem resposta do Portal Nacional (${e?.code ?? e?.message ?? "erro de rede"}).`, protocol: null };
  }
  const text = await r.body.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  const ok = r.statusCode >= 200 && r.statusCode < 300;
  return { ok, code: String(r.statusCode), message: ok ? "Evento registrado no Portal Nacional." : describeError(json, text, r.statusCode, url), protocol: json?.protocolo ?? json?.Protocolo ?? json?.idEvento ?? null };
}

