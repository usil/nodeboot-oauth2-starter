const helpers = require("./general-helpers.js");

class ExpressWrapper {
  constructor() {
    this.helpers = helpers();
  }

  createSecurePost = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathNoRoute(path);
      expressApp.set("POST" + "||" + parsedPath, allowed);
      return expressApp.post(path, guard(), ...handler);
    };
  };

  createSecureGet = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathNoRoute(path);
      expressApp.set("GET" + "||" + parsedPath, allowed);
      return expressApp.get(path, guard(), ...handler);
    };
  };

  createSecurePut = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathNoRoute(path);
      expressApp.set("PUT" + "||" + parsedPath, allowed);
      return expressApp.put(path, guard(), ...handler);
    };
  };

  createSecureDelete = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathNoRoute(path);
      expressApp.set("DELETE" + "||" + parsedPath, allowed);
      return expressApp.delete(path, guard(), ...handler);
    };
  };

  createSecurePostRouter = (expressApp, expressRouter, routePath, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathWithRoute(path);
      expressApp.set("POST" + "||" + `${routePath}${parsedPath}`, allowed);
      return expressRouter.post(path, guard(), ...handler);
    };
  };

  createSecureGetRouter = (expressApp, expressRouter, routePath, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathWithRoute(path);
      expressApp.set("GET" + "||" + `${routePath}${parsedPath}`, allowed);
      return expressRouter.get(path, guard(), ...handler);
    };
  };

  createSecurePutRouter = (expressApp, expressRouter, routePath, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathWithRoute(path);
      expressApp.set("PUT" + "||" + `${routePath}${parsedPath}`, allowed);
      return expressRouter.put(path, guard(), ...handler);
    };
  };

  createSecureDeleteRouter = (expressApp, expressRouter, routePath, guard) => {
    return (path, allowed, ...handler) => {
      const parsedPath = this.helpers.parsePathWithRoute(path);
      expressApp.set("DELETE" + "||" + `${routePath}${parsedPath}`, allowed);
      return expressRouter.delete(path, guard(), ...handler);
    };
  };
}

module.exports = ExpressWrapper;
