const authControllers = require("../src/helpers/routes/controllers");
const bcrypt = require("bcrypt");

describe("All auth controllers work", () => {
  test("Creates the user in a transaction", async () => {
    const reqBody = {
      username: "username",
      encryptedPassword: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createUserTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(3);
  });

  test("Creates the user in a transaction fails", async () => {
    const reqBody = {
      username: "username",
      encryptedPassword: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createUserTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create user", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        password: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createUser(mockedReq, mockRes);

    bcryptSpy.mockRestore();

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(knexMock.transaction).toHaveBeenCalled();
  });

  test("Create user errors", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        password: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createUser(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);

    bcryptSpy.mockRestore();
  });

  test("Creates the client in a transaction", async () => {
    const reqBody = {
      identifier: "identifier",
      encryptedAccessToken: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createClientTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(3);
  });

  test("Creates the client in a fails", async () => {
    const reqBody = {
      identifier: "identifier",
      encryptedAccessToken: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createClientTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create client", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createClient(mockedReq, mockRes);

    bcryptSpy.mockRestore();

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(knexMock.transaction).toHaveBeenCalled();
  });

  test("Create client error", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createClient(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);

    bcryptSpy.mockRestore();
  });

  test("Creates the client in a transaction", async () => {
    const reqBody = {
      identifier: "identifier",
      allowedObject: { allowed: ["*", "select"] },
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createRoleTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(2);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");
  });

  test("Creates the client in a transaction fails", async () => {
    const reqBody = {
      identifier: "identifier",
      allowedObject: { allowed: ["*", "select"] },
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createRoleTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create role", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createRole(mockedReq, mockRes);

    bcryptSpy.mockRestore();

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.transaction).toHaveBeenCalled();
  });

  test("Create client error", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createRole(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalled();

    bcryptSpy.mockRestore();
  });

  test("Create application", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplication(mockedReq, mockRes);

    bcryptSpy.mockRestore();

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Applications");
  });
});
