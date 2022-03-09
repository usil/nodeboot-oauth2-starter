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

  const oauthBoot = new OauthBoot(
    expressMock(),
    mockedKnex,
    jwtSecret,
    extraResources
  );

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
    const exp = await securityHelper.realGuard(mockReq(), res, mockNext);
    expect(exp).toBe(undefined);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      code: 403100,
      message: "Subject not authorized",
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

    expect(res.status).toHaveBeenCalledWith(403);

    expect(res.json).toHaveBeenCalledWith({
      code: 403200,
      message: "Bad guard input",
    });
  });

  test("Use is undefined", async () => {
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
      response.locals = {};
      return response;
    };

    const mockNext = jest.fn();

    const res = mockRes();

    const securityHelper = security(mockedKnex, oauthBoot.expressSecured);

    await securityHelper.realGuard(mockReq(), res, mockNext);

    expect(res.status).toHaveBeenCalledWith(403);

    expect(res.json).toHaveBeenCalledWith({
      code: 403100,
      message: "Subject not authorized",
    });
  });

  test("Complete client workflow", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });

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

    expect(res.status).toHaveBeenCalledWith(500);
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

  test("Header token given", () => {
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

    securityHelper.decodeToken(jwtSecret).decode(mockReq(), res, mockNext);

    expect(res.locals.user).toStrictEqual({
      subjectType: "user",
      username: "user",
    });

    expect(mockNext).toHaveBeenCalled();
  });

  test("Header token given incorrect", () => {
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

    securityHelper.decodeToken(jwtSecret).decode(mockReq(), res, mockNext);

    expect(res.locals.user).toBe(undefined);

    expect(res.status).toHaveBeenCalledWith(401);

    expect(res.json).toHaveBeenCalledWith({
      code: 400001,
      message: "Incorrect token",
    });
  });
});
