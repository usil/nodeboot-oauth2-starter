const security = require("../src/helpers/security.js");
const OauthBoot = require("../src/OauthBoot.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const searchMockAdmin = [
  { id: 1, applicationResource: "OAUTH2_global", allowedTerm: "*" },
];

const searchMockLocalAdmin = [
  { id: 1, applicationResource: "allowed", allowedTerm: "*" },
];

const searchMockNotAllowed = [
  { id: 1, applicationResource: "not-allowed", allowedTerm: "*" },
];

const searchMockResourceTwo = [
  { id: 1, applicationResource: "OAUTH2_global", allowedTerm: "*" },
];

const searchMockLocalSelect = [
  { id: 1, applicationResource: "allowed", allowedTerm: "select" },
];

const mockedKnex = {
  table: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  join: jest.fn().mockReturnThis(),
  where: jest.fn().mockReturnThis(),
  andWhere: jest
    .fn()
    .mockResolvedValue(searchMockAdmin)
    .mockResolvedValueOnce(searchMockAdmin)
    .mockResolvedValueOnce(searchMockLocalAdmin)
    .mockResolvedValueOnce(searchMockNotAllowed)
    .mockResolvedValueOnce(searchMockResourceTwo)
    .mockResolvedValueOnce(searchMockLocalSelect),
};

const jwtSecret = "secret";
const extraResources = ["extra"];

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

describe("Security helper works", () => {
  let token;
  beforeAll(() => {
    token = jwt.sign(
      {
        data: {
          subjectType: "user",
          username: "user",
        },
      },
      jwtSecret,
      {
        expiresIn: "1h",
      }
    );
  });

  const log = {
    debug: jest.fn(),
  };

  const oauthBoot = new OauthBoot(expressMock(), mockedKnex, log, {
    jwtSecret,
    extraResources,
    cryptoSecret: "secret",
    mainApplicationName: "OAUTH2_main_application",
    clientIdSuffix: "::client.app",
    externalErrorHandle: true,
  });

  oauthBoot.expressSecured.obPost("some-path", "allowed", () => {
    return "allowed";
  });

  oauthBoot.expressSecured.obPost("wild-path", ":", () => {
    return "allowed";
  });

  oauthBoot.expressSecured.obPost("some-path/:id", "allowed-id", () => {
    return "allowed";
  });

  oauthBoot.expressSecured.obPost("correct-path", "allowed:select", () => {
    return "allowed";
  });

  test("Gets the expression correctly", () => {
    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    const exp = securityHelper.getExpression("some-path", "POST", {});

    const expId = securityHelper.getExpression("some-path/1", "POST", {
      id: 1,
    });

    expect(exp).toBe("allowed");

    expect(expId).toBe("allowed-id");
  });

  test("Correct return when exp not found", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "non-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);
    await securityHelper.realGuard(mockReq(), res, mockNext);
    expect(mockNext).toHaveBeenCalledWith({
      message: "This endpoint does not have a valid security expression",
      statusCode: 404,
      errorCode: 404001,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: `This endpoint does not have a valid security expression. non-path parsed as security string. With method POST and params {}`,
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelperNoExternal.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({
      errorCode: 404001,
      message: "This endpoint does not have a valid security expression",
    });
  });

  test("Correct wild card", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "wild-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);
    await securityHelper.realGuard(mockReq(), res, mockNext);
    expect(mockNext).toHaveBeenCalled();
  });

  test("Incorrect auth string", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "some-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 403,
      errorCode: 403206,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: "Bad guard input, received allowed",
      message: "Bad guard input",
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelperNoExternal.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      code: 403206,
      message: "Bad guard input",
    });
  });

  test("Complete client workflow", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: false,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis().mockResolvedValueOnce([basicUser]),
      andWhere: jest.fn().mockResolvedValueOnce(searchMockLocalSelect),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);

    expect(bcryptSpy).toHaveBeenCalledTimes(1);

    bcryptSpy.mockRestore();
  });

  test("Complete client workflow, no permission", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: false,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis().mockResolvedValueOnce([basicUser]),
      andWhere: jest.fn().mockResolvedValueOnce([]),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 401,
      errorCode: 401002,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage:
        "Subject not authorized; incorrect permissions. Failed at roles and permissions validation",
      message: "Subject not authorized; incorrect permissions",
    });

    bcryptSpy.mockRestore();
  });

  test("Complete client workflow, no permission with no external", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: false,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis().mockResolvedValueOnce([basicUser]),
      andWhere: jest.fn().mockResolvedValueOnce([]),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      code: 401002,
      message: "Subject not authorized; incorrect permissions",
    });

    bcryptSpy.mockRestore();
  });

  test("Complete client workflow, incorrect token", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return false;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: false,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([basicUser]),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 403,
      errorCode: 403004,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage:
        "Incorrect token. Token was validated but failed the bcrypt comparison",
      message: "Incorrect token",
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelperNoExternal.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      code: 403104,
      message: "Incorrect token",
    });
  });

  test("Complete client workflow, client revoked", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: true,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis().mockResolvedValueOnce([basicUser]),
      andWhere: jest.fn().mockResolvedValueOnce(searchMockLocalSelect),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 403,
      errorCode: 403003,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: "Client authorization credentials have been revoked",
      message: "Client authorization credentials have been revoked",
    });

    bcryptSpy.mockRestore();
  });

  test("Complete client workflow, client revoked. No external errors", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

    const mockReq = () => {
      const request = {};
      request.path = "correct-path/";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {
        user: { subjectType: "client", identifier: "client" },
      };
      return response;
    };

    const basicUser = {
      access_token: "access",
      revoked: true,
    };

    const mockedKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis().mockResolvedValueOnce([basicUser]),
      andWhere: jest.fn().mockResolvedValueOnce(searchMockLocalSelect),
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      code: 403103,
      message: "Client authorization credentials have been revoked",
    });
    bcryptSpy.mockRestore();
  });

  test("Complete user workflow", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "correct-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = { user: { subjectType: "user", username: "user" } };
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);
  });

  test("User not found", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "correct-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = { user: null };
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 403,
      errorCode: 403002,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage:
        "Subject not authorized; no jwt token was send. This is likely a problem with the JWT",
      message: "Subject not authorized; no jwt token was send",
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelperNoExternal.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      code: 403102,
      message: "Subject not authorized; no jwt token was send",
    });
  });

  test("Handle Error", async () => {
    const mockReq = () => {
      const request = {};
      request.path = "correct-path";
      request.params = {};
      request.method = "POST";
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 500,
      errorCode: 500001,
      onFunction: "realGuard",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: "Cannot read property 'user' of undefined",
      message: "Cannot read property 'user' of undefined",
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    await securityHelperNoExternal.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      code: 500001,
      message: "Cannot read property 'user' of undefined",
    });
  });

  test("Verify rejects", () => {
    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);
    securityHelper.verify$("x", "x").catch((err) => {
      expect(err).toBeTruthy();
    });
  });

  test("No token given", () => {
    const mockReq = () => {
      const request = {};
      request.headers = {};
      request.query = {};
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {};
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    securityHelper.decodeToken(jwtSecret).decode(mockReq(), res, mockNext);

    expect(res.locals.user).toBe(undefined);

    expect(mockNext).toHaveBeenCalled();
  });

  test("Header token given", async () => {
    const mockReq = () => {
      const request = {};
      request.headers = { authorization: `BEARER ${token}` };
      request.query = {};
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {};
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper
      .decodeToken(jwtSecret)
      .decode(mockReq(), res, mockNext);

    expect(res.locals.user).toStrictEqual({
      subjectType: "user",
      username: "user",
    });

    expect(mockNext).toHaveBeenCalled();
  });

  test("Header token given incorrect", async () => {
    const mockReq = () => {
      const request = {};
      request.headers = { authorization: `BEARER false-token` };
      request.query = {};
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {};
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    securityHelper.verify$ = jest
      .fn()
      .mockRejectedValue({ message: "SOME JWT ERROR" });

    await securityHelper
      .decodeToken(jwtSecret)
      .decode(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 401,
      errorCode: 400001,
      onFunction: "decodeToken",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: "SOME JWT ERROR",
      message: "SOME JWT ERROR",
    });

    securityHelper.verify$ = jest
      .fn()
      .mockRejectedValue({ message: "SOME JWT ERROR", expiredAt: "some date" });

    await securityHelper
      .decodeToken(jwtSecret)
      .decode(mockReq(), res, mockNext);

    expect(mockNext).toHaveBeenCalledWith({
      statusCode: 401,
      errorCode: 400002,
      onFunction: "decodeToken",
      onLibrary: "nodeboot-oauth2-starter",
      onFile: "security.js",
      originalError: undefined,
      errorObject: undefined,
      logMessage: "SOME JWT ERROR expired at some date",
      message: "SOME JWT ERROR",
    });

    const securityHelperNoExternal = security(
      mockedKnex,
      oauthBoot.expressSecured,
      false
    );

    securityHelperNoExternal.verify$ = jest
      .fn()
      .mockRejectedValue({ message: "SOME JWT ERROR" });

    await securityHelperNoExternal
      .decodeToken(jwtSecret)
      .decode(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      code: 400001,
      message: "SOME JWT ERROR",
    });

    securityHelperNoExternal.verify$ = jest
      .fn()
      .mockRejectedValue({ message: "SOME JWT ERROR", expiredAt: "some date" });
    await securityHelperNoExternal
      .decodeToken(jwtSecret)
      .decode(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      code: 400002,
      message: "SOME JWT ERROR expired at some date",
    });
  });
});
