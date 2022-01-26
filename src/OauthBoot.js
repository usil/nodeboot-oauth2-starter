const ExpressWrapper = require("./helpers/ExpressWrapper.js");
const security = require("./helpers/security.js");
const tableCreation = require("./helpers/table-creation.js");

class OauthBoot {
  constructor(expressApp, knex, jwtSecret, extraParts = []) {
    this.expressApp = expressApp;
    this.knex = knex;
    const expressWrapper = new ExpressWrapper();
    this.expressSecured = this.bootOauthExpress(expressApp, expressWrapper);
    this.jwtSecret = jwtSecret;
    this.extraParts = extraParts;
    this.expiresIn = "24h";
    this.tableCreationHelper = tableCreation(
      this.knex,
      this.jwtSecret,
      this.extraParts
    );
  }

  setTokenExpirationTime(timeString) {
    this.expiresIn = timeString;
  }

  bootOauthExpress(expressApp, expressWrapper) {
    expressApp.obPost = expressWrapper.createSecurePost(
      expressApp,
      security(this.knex, this.expressSecured).guard
    );

    expressApp.obGet = expressWrapper.createSecureGet(
      expressApp,
      security(this.knex, this.expressSecured).guard
    );

    expressApp.obPut = expressWrapper.createSecurePut(
      expressApp,
      security(this.knex, this.expressSecured).guard
    );

    expressApp.obDelete = expressWrapper.createSecureDelete(
      expressApp,
      security(this.knex, this.expressSecured).guard
    );

    return expressApp;
  }

  bootOauthExpressRouter(expressRouter) {
    const expressWrapper = new ExpressWrapper();

    expressRouter.obPost = expressWrapper.createSecurePostRouter(
      this.expressApp,
      expressRouter,
      security(this.knex, this.expressSecured).guard
    );

    expressRouter.obGet = expressWrapper.createSecureGetRouter(
      this.expressApp,
      expressRouter,
      security(this.knex, this.expressSecured).guard
    );

    expressRouter.obPut = expressWrapper.createSecurePutRouter(
      this.expressApp,
      expressRouter,
      security(this.knex, this.expressSecured).guard
    );

    expressRouter.obDelete = expressWrapper.createSecureDeleteRouter(
      this.expressApp,
      expressRouter,
      security(this.knex, this.expressSecured).guard
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
      // this.addEndPoints();
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }
}

module.exports = OauthBoot;
