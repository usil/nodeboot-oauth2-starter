const ExpressWrapper = require("./helpers/ExpressWrapper.js");
const security = require("./helpers/security.js");
const tableCreation = require("./helpers/table-creation.js");
const authSecureRoutes = require("./helpers/routes/routes.js");
const generalHelpers = require("./helpers/general-helpers.js");
class OauthBoot {
  constructor(expressApp, knex, jwtSecret, cryptoSecret, extraParts = []) {
    this.cryptoSecret = cryptoSecret;
    this.expressApp = expressApp;
    this.knex = knex;
    const expressWrapper = new ExpressWrapper();
    this.expressSecured = this.bootOauthExpress(expressApp, expressWrapper);
    this.jwtSecret = jwtSecret;
    this.extraParts = extraParts;
    this.expiresIn = "24h";
    this.tableCreationHelper = tableCreation(
      this.knex,
      this.cryptoSecret,
      this.extraParts
    );
  }

  setTokenExpirationTime(timeString) {
    this.expiresIn = timeString;
  }

  bootOauthExpress(expressApp, expressWrapper) {
    expressApp.obPost = expressWrapper.createSecurePost(
      expressApp,
      security(this.knex, this.expressApp).guard
    );

    expressApp.obGet = expressWrapper.createSecureGet(
      expressApp,
      security(this.knex, this.expressApp).guard
    );

    expressApp.obPut = expressWrapper.createSecurePut(
      expressApp,
      security(this.knex, this.expressApp).guard
    );

    expressApp.obDelete = expressWrapper.createSecureDelete(
      expressApp,
      security(this.knex, this.expressApp).guard
    );

    return expressApp;
  }

  bootOauthExpressRouter(expressRouter, routePath) {
    const expressWrapper = new ExpressWrapper();

    expressRouter.obPost = expressWrapper.createSecurePostRouter(
      this.expressApp,
      expressRouter,
      routePath,
      security(this.knex, this.expressApp).guard
    );

    expressRouter.obGet = expressWrapper.createSecureGetRouter(
      this.expressApp,
      expressRouter,
      routePath,
      security(this.knex, this.expressApp).guard
    );

    expressRouter.obPut = expressWrapper.createSecurePutRouter(
      this.expressApp,
      expressRouter,
      routePath,
      security(this.knex, this.expressApp).guard
    );

    expressRouter.obDelete = expressWrapper.createSecureDeleteRouter(
      this.expressApp,
      expressRouter,
      routePath,
      security(this.knex, this.expressApp).guard
    );

    return expressRouter;
  }

  async init() {
    try {
      await this.tableCreationHelper.auditDataBase();

      this.expressSecured.use(
        security(this.knex, this.expressSecured).decodeToken(this.jwtSecret)
          .decode
      );

      const helper = generalHelpers();

      authSecureRoutes(
        this.expressSecured,
        this.knex,
        helper.validateBody,
        this.jwtSecret,
        this.expiresIn,
        this.cryptoSecret
      );
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }
}

module.exports = OauthBoot;
