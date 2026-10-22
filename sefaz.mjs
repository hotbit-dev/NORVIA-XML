import { request } from "undici";
import { XMLParser } from "fast-xml-parser";

export const SEFAZ_SERVICES = {
  nfe: { name: "NFe", layout: "1.01", producao: "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx", homologacao: "https://hom1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx" },
  cte: { name: "CTe", layout: "1.00", producao: "https://www1.cte.fazenda.gov.br/CTeDistribuicaoDFe/CTeDistribuicaoDFe.asmx", homologacao: "https://hom1.cte.fazenda.gov.br/CTeDistribuicaoDFe/CTeDistribuicaoDFe.asmx" },
  mdfe: { name: "MDFe", layout: "1.00", producao: "https://mdfe.svrs.rs.gov.br/ws/MDFeDistribuicaoDFe/MDFeDistribuicaoDFe.asmx", homologacao: "https://mdfe-homologacao.svrs.rs.gov.br/ws/MDFeDistribuicaoDFe/MDFeDistribuicaoDFe.asmx" },
};
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", removeNSPrefix: true, parseTagValue: false, processEntities: false });

export function distributionEnvelope(body) {
  const service = SEFAZ_SERVICES[body.source];
  if (!service || !["producao", "homologacao"].includes(body.environment)) throw new Error("Serviço SEFAZ inválido.");
  const cnpj = String(body.cnpj ?? "");
  const nsu = String(body.nsu ?? "0");
  const uf = String(body.uf_code ?? "");
  if (!/^\d{14}$/.test(cnpj) || !/^\d{1,15}$/.test(nsu) || !/^\d{2}$/.test(uf)) throw new Error("CNPJ, UF ou NSU inválido para consulta SEFAZ.");
  const prefix = body.source;
  const namespace = `http://www.portalfiscal.inf.br/${prefix}/wsdl/${service.name}DistribuicaoDFe`;
  const operation = `${prefix}DistDFeInteresse`;
  const action = `${namespace}/${operation}`;
  const authorUf = prefix === "mdfe" ? "" : `<cUFAutor>${uf}</cUFAutor>`;
  const payload = `<distDFeInt versao="${service.layout}" xmlns="http://www.portalfiscal.inf.br/${prefix}"><tpAmb>${body.environment === "producao" ? 1 : 2}</tpAmb>${authorUf}<CNPJ>${cnpj}</CNPJ><distNSU><ultNSU>${nsu.padStart(15, "0")}</ultNSU></distNSU></distDFeInt>`;
  return { url: service[body.environment], action, xml: `<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><${operation} xmlns="${namespace}"><${prefix}DadosMsg>${payload}</${prefix}DadosMsg></${operation}></soap12:Body></soap12:Envelope>` };
}

function findRet(value) {
  if (!value || typeof value !== "object") return null;
  if (value.retDistDFeInt) return typeof value.retDistDFeInt === "string" ? findRet(parser.parse(value.retDistDFeInt)) : value.retDistDFeInt;
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string" && /Result$/.test(key) && item.includes("retDistDFeInt")) { const found = findRet(parser.parse(item)); if (found) return found; }
    const found = findRet(item); if (found) return found;
  }
  return null;
}
export function parseDistributionResponse(xml) {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("Resposta XML SEFAZ inválida.");
  const ret = findRet(parser.parse(xml));
  if (!ret) throw new Error("Resposta inesperada do serviço SEFAZ.");
  const docs = ret.loteDistDFeInt?.docZip;
  const list = docs ? Array.isArray(docs) ? docs : [docs] : [];
  return { code: String(ret.cStat ?? ""), message: String(ret.xMotivo ?? ""), last_nsu: String(ret.ultNSU ?? "0"), max_nsu: String(ret.maxNSU ?? "0"), documents: list.map(d => ({ nsu: String(d["@NSU"] ?? ""), schema: String(d["@schema"] ?? ""), xml_base64: String(d["#text"] ?? "") })) };
}
export async function sefazDistribution(body, dispatcher) {
  const { url, action, xml } = distributionEnvelope(body);
  const response = await request(url, { method: "POST", dispatcher, headersTimeout: 30000, bodyTimeout: 30000, headers: { "content-type": `application/soap+xml; charset=utf-8; action="${action}"`, accept: "application/soap+xml" }, body: xml });
  const raw = await response.body.text();
  if (response.statusCode !== 200) throw new Error(`SEFAZ indisponível (HTTP ${response.statusCode}).`);
  return parseDistributionResponse(raw);
}
