const authControllers = require("../src/helpers/routes/controllers.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

describe("All auth controllers work", () => {
  test("Handle error", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleError("error", 500000, 500, "test");

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(500);
    expect(errorOne.errorCode).toBe(500000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleError(
      "error",
      500000,
      500,
      "test"
    );

    expect(errorTwo.message).toBe("error");
    expect(errorTwo.code).toBe(500000);
  });

  test("Handle error 500", () => {
    const knex = {};

    const testError = new Error("test");

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleError500(500000, testError, "test");

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(500);
    expect(errorOne.errorCode).toBe(500000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleError500(
      500000,
      testError,
      "test"
    );

    expect(errorTwo.message).toBe("test");
    expect(errorTwo.code).toBe(500000);
  });

  test("Handle error 409", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleNotUniqueError409(
      "test",
      400000,
      "test"
    );

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(409);
    expect(errorOne.errorCode).toBe(400000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleNotUniqueError409(
      "test",
      400000,
      "test"
    );

    expect(errorTwo.message).toBe(`That test is already on use`);
    expect(errorTwo.code).toBe(400000);
  });

  test("Call next or res", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    const jsonCall = { message: "ok" };

    controllers.callNextOrResOnError(res, next, jsonCall);

    expect(next).toHaveBeenCalledWith(jsonCall);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    controllersNoExternal.callNextOrResOnError(res, next, jsonCall, 400);

    expect(res.json).toHaveBeenCalledWith(jsonCall);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test("Update password", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockResolvedValue([1])
        .mockResolvedValueOnce([{ password: "1234" }]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    await controllers.updatePassword(req, res);

    expect(res.status).toHaveBeenCalledWith(201);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(knex.update).toHaveBeenCalledWith({ password: "hashed" });

    expect(bcryptSpyCompare).toHaveBeenCalled();
    expect(bcryptSpyHash).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password, user does not exist", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updatePassword(req, res);

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    expect(controllers.handleError).toHaveBeenCalledWith(
      "User does not exist",
      404006,
      404,
      "updatePassword"
    );

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password incorrect original password", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockResolvedValue([1])
        .mockResolvedValueOnce([{ password: "1234" }]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return false;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updatePassword(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect password",
      401002,
      401,
      "updatePassword"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password fails", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updatePassword(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });


  test("Login works", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.login(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(bcryptSpy).toHaveBeenCalled();
    expect(jwtSpy).toHaveBeenCalled();
    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Users");

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login, username does not exist", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.login(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Username does not exist",
      404007,
      404,
      "login"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login, incorrect password", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return false;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.login(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect password",
      401001,
      401,
      "login"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login fails", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      throw new Error("Async error");
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.login(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });
  
});
