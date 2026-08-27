"use strict";

const JsoProtectorWebpackPlugin = require("./webpack.js");

function withJsoProtector(nextConfig = {}, options = {}) {
  if (typeof nextConfig === "function") {
    return async (...args) => {
      const resolved = await nextConfig(...args);
      return applyJsoProtector(resolved, options);
    };
  }

  return applyJsoProtector(nextConfig, options);
}

function applyJsoProtector(nextConfig = {}, options = {}) {
  const baseConfig = nextConfig || {};
  const userWebpack = baseConfig.webpack;

  return {
    ...baseConfig,
    webpack(config, context) {
      const nextWebpackConfig = typeof userWebpack === "function"
        ? userWebpack(config, context)
        : config;
      const resolvedConfig = nextWebpackConfig || config || {};

      if (!shouldApplyPlugin(context, options)) {
        return resolvedConfig;
      }

      const plugins = Array.isArray(resolvedConfig.plugins) ? resolvedConfig.plugins.slice() : [];
      plugins.push(new JsoProtectorWebpackPlugin(options));

      return {
        ...resolvedConfig,
        plugins
      };
    }
  };
}

function shouldApplyPlugin(context = {}, options = {}) {
  if (options.applyInDevelopment === true) {
    return matchesTarget(context, options.target);
  }

  if (context.dev) {
    return false;
  }

  return matchesTarget(context, options.target);
}

function matchesTarget(context = {}, target = "client") {
  const normalizedTarget = String(target || "client").toLowerCase();
  if (normalizedTarget === "both") return true;
  if (normalizedTarget === "server") return !!context.isServer;
  return !context.isServer;
}

module.exports = withJsoProtector;
module.exports.withJsoProtector = withJsoProtector;
module.exports.default = withJsoProtector;
