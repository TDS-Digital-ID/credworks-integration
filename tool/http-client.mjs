import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
// The optional TLS dependencies are only for mapped fixture networking. Normal
// callers retain platform CA and hostname checks; redirects are never followed.
export function httpClient(
  tls = {},
  managementOrigin,
  now = () => Date.now() / 1000,
) {
  if (Object.keys(tls).some((key) => !["ca", "lookup", "port"].includes(key)))
    throw Error("HTTPS_OPTIONS_REFUSED");
  return (location, options = {}) =>
    new Promise((resolve, reject) => {
      const responseLimit = options.responseLimit ?? 131072;
      if (![131072, 262144].includes(responseLimit))
        return reject(Error("HTTP_RESPONSE_LIMIT_REFUSED"));
      const url = new URL(location);
      const management =
        url.protocol === "http:" &&
        url.hostname === "127.0.0.1" &&
        url.origin === managementOrigin;
      if (
        (url.protocol !== "https:" && !management) ||
        url.username ||
        url.password ||
        url.hash
      )
        return reject(Error("HTTP_LOCATION_REFUSED"));
      const request = management ? httpRequest : httpsRequest;
      const requestLimit = options.requestLimit ?? 131072;
      if (![131072, 262144].includes(requestLimit))
        return reject(Error("HTTP_REQUEST_LIMIT_REFUSED"));
      const body = options.body;
      if (body && Buffer.byteLength(body) > requestLimit)
        return reject(Error("HTTP_REQUEST_TOO_LARGE"));
      const req = request(
        url,
        {
          ...tls,
          agent: false,
          method: options.method ?? "GET",
          headers: options.headers,
        },
        (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400) {
            res.destroy();
            return reject(Error("HTTP_REDIRECT_REFUSED"));
          }
          let bytes = 0;
          const chunks = [];
          res.on("data", (chunk) => {
            bytes += chunk.length;
            if (bytes > responseLimit) {
              res.destroy();
              reject(Error("HTTP_RESPONSE_TOO_LARGE"));
            } else chunks.push(chunk);
          });
          res.on("end", () => {
            clearTimeout(timer);
            const text = Buffer.concat(chunks).toString("utf8");
            resolve({
              status: res.statusCode,
              headers: res.headers,
              text,
              json: () => JSON.parse(text),
            });
          });
          res.on("error", () => {
            clearTimeout(timer);
            reject(Error("HTTP_TRANSPORT_UNAVAILABLE"));
          });
        },
      );
      const timer = setTimeout(
        () => req.destroy(Error("HTTP_DEADLINE_EXCEEDED")),
        10000,
      );
      req.on("error", () => {
        clearTimeout(timer);
        reject(Error("HTTP_TRANSPORT_UNAVAILABLE"));
      });
      req.on("close", () => clearTimeout(timer));
      if (body && options.deadline !== undefined) {
        req.once("socket", (socket) => {
          const write = () => {
            if (
              !Number.isFinite(options.deadline) ||
              now() >= options.deadline
            ) {
              reject(Error("FRESHNESS_CHECK_FAILED"));
              req.destroy();
            } else req.end(body);
          };
          socket.once(management ? "connect" : "secureConnect", write);
        });
        req.flushHeaders();
      } else req.end(body);
    });
}
