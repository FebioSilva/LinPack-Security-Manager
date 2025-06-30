const path = require("path");

module.exports = {
  entry: "./src/index.js",
  output: {
    filename: "bundle.js",
    path: path.resolve(__dirname, "dist"),
  },
  mode: "development",
  devServer: {
    static: {
      directory: path.resolve(__dirname, "../app"),
    },
    port: 3000,
    proxy: [
      {
        context: '/sparql',  // string aqui (pode ser array se quiser)
        target: 'http://localhost:8890',
        changeOrigin: true,
        secure: false,
        logLevel: 'debug',
      }
    ]
  },
};
