const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "public");

function ping(cb) {
  https.get("https://registry.example.org/-/ping", (res) => cb(res.statusCode));
}

http
  .createServer((req, res) => {
    const p = path.join(ROOT, path.normalize(req.url).replace(/^(\.\.[\/\\])+/, ""));
    if (!p.startsWith(ROOT)) {
      res.statusCode = 403;
      return res.end();
    }
    fs.readFile(p, (err, data) => {
      if (err) {
        res.statusCode = 404;
        return res.end();
      }
      res.end(data);
    });
  })
  .listen(8000);
