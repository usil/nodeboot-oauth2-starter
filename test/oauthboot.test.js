const ExpressWrapper = require("../src/helpers/ExpressWrapper.js");
const OauthBoot = require("../src/OauthBoot.js");

const mockedKnex = {};
const jwtSecret = "secret";
const extraParts = ["extra"];

const expressMock = () => {
  const express = { getMemory: {} };

  express.get = jest.fn().mockImplementation((stringToGet) => {
    return express.getMemory[stringToGet];
  });

  express.post = jest.fn();

  express.put = jest.fn();

  express.delete = jest.fn();

  express.set = (stringToGet, valueToSet) => {
    express.getMemory[stringToGet] = valueToSet;
  };

  return express;
};

describe("OauthBoot class and his functions work as required", () => {
  beforeAll(() => {});
  test("Correct variable assignation", () => {
    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnex,
      jwtSecret,
      extraParts
    );

    expect(oauthBoot.jwtSecret).toBe("secret");
    expect(oauthBoot.extraParts).toStrictEqual(["extra"]);
    expect(oauthBoot.expressApp).toBeTruthy();
    expect(oauthBoot.knex).toBeTruthy();
    expect(oauthBoot.expiresIn).toBe("24h");
  });
  test("Sets token exp time", () => {
    const oauthBoot = new OauthBoot(
      expressMock,
      mockedKnex,
      jwtSecret,
      extraParts
    );
    oauthBoot.setTokenExpirationTime("20h");
    expect(oauthBoot.expiresIn).toBe("20h");
  });
  test("Creates boot express at start", () => {
    jest.spyOn(OauthBoot.prototype, "bootOauthExpress");
    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnex,
      jwtSecret,
      extraParts
    );
    expect(oauthBoot.bootOauthExpress).toHaveBeenCalledTimes(1);
    jest.restoreAllMocks();
  });
  test("Creates boot express", () => {
    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnex,
      jwtSecret,
      extraParts
    );
    const expressWrapper = {
      createSecurePost: jest.fn(),
      createSecureGet: jest.fn(),
      createSecurePut: jest.fn(),
      createSecureDelete: jest.fn(),
    };
    oauthBoot.bootOauthExpress(oauthBoot.expressApp, expressWrapper);
    expect(expressWrapper.createSecureDelete).toHaveBeenCalledTimes(1);
    expect(expressWrapper.createSecureGet).toHaveBeenCalledTimes(1);
    expect(expressWrapper.createSecurePost).toHaveBeenCalledTimes(1);
    expect(expressWrapper.createSecurePut).toHaveBeenCalledTimes(1);
  });
  test("Creates boot express for router", () => {
    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnex,
      jwtSecret,
      extraParts
    );

    const expressRouter = {};

    oauthBoot.bootOauthExpressRouter(expressRouter);

    expect(expressRouter.obPost).toBeTruthy();
  });
  test("It does not need extra parts", () => {
    const oauthBoot = new OauthBoot(expressMock(), mockedKnex, jwtSecret);
    expect(oauthBoot.jwtSecret).toBe("secret");
    expect(oauthBoot.extraParts).toStrictEqual([]);
    expect(oauthBoot.expressApp).toBeTruthy();
    expect(oauthBoot.knex).toBeTruthy();
    expect(oauthBoot.expiresIn).toBe("24h");
  });

  test("Init works", async () => {
    const mockedKnexSchema = () => {
      const knex = {
        schema: {
          dropTableIfExists: jest.fn(),
          hasTable: jest.fn(),
        },
      };

      return knex;
    };

    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnexSchema(),
      jwtSecret
    );

    oauthBoot.tableCreationHelper.auditDataBase = jest.fn();
    oauthBoot.expressSecured.use = jest.fn();

    await oauthBoot.init();

    expect(oauthBoot.expressSecured.use).toHaveBeenCalledTimes(1);
    expect(oauthBoot.tableCreationHelper.auditDataBase).toHaveBeenCalledTimes(
      1
    );
  });

  test("Init error works", async () => {
    const mockedKnexSchema = () => {
      const knex = {
        schema: {
          dropTableIfExists: jest.fn(),
          hasTable: jest.fn(),
        },
      };

      return knex;
    };

    const oauthBoot = new OauthBoot(
      expressMock(),
      mockedKnexSchema(),
      jwtSecret
    );

    oauthBoot.tableCreationHelper.auditDataBase = jest
      .fn()
      .mockImplementation(async () => {
        throw new Error("Some Error");
      });
    oauthBoot.expressSecured.use = jest.fn();

    await expect(oauthBoot.init()).rejects.toThrow();
  });
});
