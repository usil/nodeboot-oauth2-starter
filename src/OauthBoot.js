const ExpressWrapper = require("./helpers/ExpressWrapper.js");
const security = require("./helpers/security.js");
const tableCreation = require("./helpers/table-creation.js");
const authSecureRoutes = require("./helpers/routes/routes.js");
const authControllers = require("./helpers/routes/controllers.js");
const generalHelpers = require("./helpers/general-helpers.js");
class OauthBoot {
  constructor(
    expressApp,
    knex,
    log,
    options = {
      jwtSecret: "secret",
      cryptoSecret: "cryptoSecret",
      extraResources: [],
      mainApplicationName: "OAUTH2_main_application",
      clientIdSuffix: "::client.app",
      externalErrorHandle: true,
      expiresIn: "24h",
    }
  ) {
    this.log = log || console;

    let safeOptionsToLog = JSON.parse(JSON.stringify(options))
    safeOptionsToLog.jwtSecret = "***";
    safeOptionsToLog.cryptoSecret = "***";

    this.log.debug("Oauth2 options", safeOptionsToLog);
    this.externalErrorHandle = options.externalErrorHandle;
    this.cryptoSecret = options.cryptoSecret;
    this.expressApp = expressApp;
    this.knex = knex;
    const expressWrapper = new ExpressWrapper();
    this.security = security(
      this.knex,
      this.expressApp,
      this.externalErrorHandle
    );
    this.expressSecured = this.bootOauthExpress(expressApp, expressWrapper);
    this.jwtSecret = options.jwtSecret;
    this.extraResources = options.extraResources || [];
    this.expiresIn = options.expiresIn || "24h";
    this.mainApplicationName =
      options.mainApplicationName || "OAUTH2_main_application";
    this.clientIdSuffix = options.clientIdSuffix || "::client.app";
    this.tableCreationHelper = tableCreation(
      this.knex,
      this.cryptoSecret,
      this.extraResources,
      this.mainApplicationName,
      this.clientIdSuffix,
      this.log
    );
  }

  setTokenExpirationTime(timeString) {
    this.expiresIn = timeString;
  }

  bootOauthExpress(expressApp, expressWrapper) {
    expressApp.obPost = expressWrapper.createSecurePost(
      expressApp,
      this.security.guard
    );

    expressApp.obGet = expressWrapper.createSecureGet(
      expressApp,
      this.security.guard
    );

    expressApp.obPut = expressWrapper.createSecurePut(
      expressApp,
      this.security.guard
    );

    expressApp.obDelete = expressWrapper.createSecureDelete(
      expressApp,
      this.security.guard
    );

    return expressApp;
  }

  bootOauthExpressRouter(expressRouter, routePath) {
    const expressWrapper = new ExpressWrapper();

    expressRouter.obPost = expressWrapper.createSecurePostRouter(
      this.expressApp,
      expressRouter,
      routePath,
      this.security.guard
    );

    expressRouter.obGet = expressWrapper.createSecureGetRouter(
      this.expressApp,
      expressRouter,
      routePath,
      this.security.guard
    );

    expressRouter.obPut = expressWrapper.createSecurePutRouter(
      this.expressApp,
      expressRouter,
      routePath,
      this.security.guard
    );

    expressRouter.obDelete = expressWrapper.createSecureDeleteRouter(
      this.expressApp,
      expressRouter,
      routePath,
      this.security.guard
    );

    return expressRouter;
  }

  async init() {
    try {
      await this.tableCreationHelper.auditDataBase();

      this.expressSecured.use(this.security.decodeToken(this.jwtSecret).decode);

      const helper = generalHelpers();

      const controller = authControllers(
        this.knex,
        this.jwtSecret,
        this.expiresIn,
        this.cryptoSecret,
        this.clientIdSuffix,
        this.log
      );

      authSecureRoutes(this.expressSecured, helper.validateBody, controller);
    } catch (error) {
      this.log.error("Error on init", error);
      throw new Error(error.message);
    }
  }
}

module.exports = OauthBoot;
