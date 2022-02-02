class ExpressWrapper {
  constructor() {}

  createSecurePost = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("POST" + "||" + path, allowed);
      return expressApp.post(path, guard(), ...handler);
    };
  };

  createSecureGet = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("GET" + "||" + path, allowed);
      return expressApp.get(path, guard(), ...handler);
    };
  };

  createSecurePut = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("PUT" + "||" + path, allowed);
      return expressApp.put(path, guard(), ...handler);
    };
  };

  createSecureDelete = (expressApp, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("DELETE" + "||" + path, allowed);
      return expressApp.delete(path, guard(), ...handler);
    };
  };

  createSecurePostRouter = (expressApp, expressRouter, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("POST" + "||" + path, allowed);
      return expressRouter.post(path, guard(), ...handler);
    };
  };

  createSecureGetRouter = (expressApp, expressRouter, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("GET" + "||" + path, allowed);
      return expressRouter.get(path, guard(), ...handler);
    };
  };

  createSecurePutRouter = (expressApp, expressRouter, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("PUT" + "||" + path, allowed);
      return expressRouter.put(path, guard(), ...handler);
    };
  };

  createSecureDeleteRouter = (expressApp, expressRouter, guard) => {
    return (path, allowed, ...handler) => {
      expressApp.set("DELETE" + "||" + path, allowed);
      return expressRouter.delete(path, guard(), ...handler);
    };
  };
}

module.exports = ExpressWrapper;
