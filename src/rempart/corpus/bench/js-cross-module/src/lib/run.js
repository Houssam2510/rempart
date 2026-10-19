const { exec } = require("child_process");

function convert(file) {
  // rempart-alt: CODE-CMD-INJECTION
  return exec("convert " + file + " out.png");
}

module.exports = { convert };
