const authControllers = require("../../src/helpers/routes/controllers");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

describe('Controllers - token', () => {
    test("Token generator non grant type", async () => {
        const req = {
          body: {
            grant_type: "none",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.token(req, res);
    
        expect(controllers.handleError).toHaveBeenCalledWith(
          "Unsupported grand type",
          400002,
          400,
          "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
      });
    
    test("Token generator clients", async () => {
        const req = {
            body: {
            grant_type: "client_credentials",
            client_id: 1,
            client_secret: "secret",
            },
        };

        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        const knex = {};

        const controllers = authControllers(knex, "secret");
        controllers.handleClientToken = jest
            .fn()
            .mockResolvedValue([{ result: "result" }, null]);
        await controllers.token(req, res);

        expect(res.status).toHaveBeenCalledWith(201);
        expect(res.json).toHaveBeenCalledWith({
            message: `Token generated for client ${1}`,
            code: 200000,
            content: { result: "result" },
        });
    });
    test("Token generator clients error 401100", async () => {
        const req = {
            body: {
            grant_type: "client_credentials",
            client_id: 1,
            client_secret: "secret",
            },
        };

        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        const knex = {};

        const controllers = authControllers(knex, "secret");
        controllers.handleClientToken = jest.fn().mockResolvedValue([null, 401100]);

        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();

        await controllers.token(req, res);

        expect(controllers.handleError).toHaveBeenCalledWith(
            "Incorrect client secret",
            401100,
            401,
            "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });

    test("Token generator clients error 403100", async () => {
        const req = {
            body: {
            grant_type: "client_credentials",
            client_id: 1,
            client_secret: "secret",
            },
        };

        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        const knex = {};

        const controllers = authControllers(knex, "secret");
        controllers.handleClientToken = jest.fn().mockResolvedValue([null, 403100]);

        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();

        await controllers.token(req, res);

        expect(controllers.handleError).toHaveBeenCalledWith(
            "Client is not able to generate tokens, use your long live token",
            403100,
            403,
            "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    test("Token generator clients error 404100", async () => {
        const req = {
          body: {
            grant_type: "client_credentials",
            client_id: 1,
            client_secret: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
        controllers.handleClientToken = jest.fn().mockResolvedValue([null, 404100]);
    
        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
    
        await controllers.token(req, res);
    
        expect(controllers.handleError).toHaveBeenCalledWith(
          `Client with id 1 not found`,
          404100,
          404,
          "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    
    test("Token generator clients error", async () => {
        const req = {
          body: {
            grant_type: "client_credentials",
            client_id: 1,
            client_secret: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
        controllers.handleClientToken = jest
          .fn()
          .mockResolvedValue([null, "Some Error"]);
        controllers.handleError500 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.token(req, res);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    test("Token generator users", async () => {
        const req = {
          body: {
            grant_type: "password",
            username: "username",
            password: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
    
        controllers.handleUserToken = jest
          .fn()
          .mockResolvedValue([{ result: "result" }, null]);
    
        await controllers.token(req, res);
    
        expect(res.status).toHaveBeenCalledWith(201);
        expect(res.json).toHaveBeenCalledWith({
          message: `Token generated for user username`,
          code: 200000,
          content: { result: "result" },
        });
    });
    
    test("Token generator users error 401200", async () => {
        const req = {
          body: {
            grant_type: "password",
            username: "username",
            password: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
    
        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
    
        controllers.handleUserToken = jest.fn().mockResolvedValue([null, 401200]);
    
        await controllers.token(req, res);
    
        expect(controllers.handleError).toHaveBeenCalledWith(
          "Incorrect user password",
          401200,
          401,
          "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    test("Token generator users error 404200", async () => {
        const req = {
          body: {
            grant_type: "password",
            username: "username",
            password: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
    
        controllers.handleError = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
    
        controllers.handleUserToken = jest.fn().mockResolvedValue([null, 404200]);
    
        await controllers.token(req, res);
    
        expect(controllers.handleError).toHaveBeenCalledWith(
          "User not found",
          404200,
          404,
          "token"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    
    test("Token generator users error", async () => {
        const req = {
          body: {
            grant_type: "password",
            username: "username",
            password: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
    
        controllers.handleUserToken = jest
          .fn()
          .mockResolvedValue([null, "Some error"]);
        controllers.handleError500 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.token(req, res);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    
    test("Token generator fails", async () => {
        const req = {
          body: {
            grant_type: "password",
            username: "username",
            password: "secret",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {};
    
        const controllers = authControllers(knex, "secret");
    
        controllers.handleUserToken = jest
          .fn()
          .mockRejectedValue(new Error("Async error"));
        controllers.handleError500 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.token(req, res);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    test("Generate long live token", async () => {
        const bcryptSpy = jest.spyOn(bcrypt, "hash").mockReturnValue(true);
    
        const req = {
          query: {},
          params: { id: 1 },
          body: {
            identifier: "identifier",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knexMock = {
          table: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockResolvedValue([{ client_id: 1 }]),
        };
    
        const controllers = authControllers(knexMock, "secret");
    
        await controllers.generateLongLive(req, res);
    
        expect(res.status).toHaveBeenCalledWith(201);
    
        expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
        expect(knexMock.update).toHaveBeenCalled();
        expect(knexMock.where).toHaveBeenCalledWith("OAUTH2_Clients.id", "=", 1);
        expect(knexMock.where).toHaveBeenCalledWith("id", 1);
        bcryptSpy.mockRestore();
    });
    
    test("Handle user token", async () => {
        const username = "username";
        const password = "password";
        const bcryptSpy = jest.spyOn(bcrypt, "compare").mockReturnValue(true);
        const jwtSpy = jest.spyOn(jwt, "sign").mockReturnValue("token");
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockResolvedValue([
            {
              id: 1,
              username: "someUser",
              roles: "someRole",
              description: "some description",
              name: "someName",
            },
          ]),
        };
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleUserToken(username, password);
    
        expect(bcryptSpy).toHaveBeenCalled();
        expect(result).toStrictEqual([
          {
            jwt_token: "token",
            name: "someName",
            description: "some description",
            user_id: 1,
            username: "someUser",
            roles: ["someRole"],
          },
          null,
        ]);
        bcryptSpy.mockRestore();
        jwtSpy.mockRestore();
    });
    
    test("Remove long live token", async () => {
        const req = {
          query: {
            remove_long_live: "true",
          },
          params: { id: 1 },
          body: {
            identifier: "identifier",
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          where: jest.fn().mockResolvedValue("some"),
        };
    
        const controllers = authControllers(knex, "secret");
        await controllers.generateLongLive(req, res);
    
        expect(res.status).toHaveBeenCalledWith(201);
        expect(res.json).toHaveBeenCalledWith({
          message: `Token removed`,
          code: 200001,
        });
    
        expect(knex.table).toHaveBeenCalledWith("OAUTH2_Clients");
        expect(knex.update).toHaveBeenCalledWith({
          access_token: null,
        });
        expect(knex.where).toHaveBeenCalledWith("OAUTH2_Clients.id", "=", 1);
    });
    
    test("Remove long live token fails", async () => {
        const req = {
          query: {
            remove_long_live: "true",
          },
          body: {
            identifier: "identifier",
            client_id: 1,
          },
        };
    
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          where: jest.fn().mockRejectedValue(new Error("Async error")),
        };
    
        const controllers = authControllers(knex, "secret");
        controllers.handleError500 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.generateLongLive(req, res);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    
    test("Handle user token 404200", async () => {
        const username = "username";
        const password = "password";
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockResolvedValue([]),
        };
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleUserToken(username, password);
    
        expect(result).toStrictEqual([null, 404200]);
    });
    
    test("Handle user token 401200", async () => {
        const username = "username";
        const password = "password";
        const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
          return false;
        });
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockResolvedValue([1]),
        };
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleUserToken(username, password);
    
        expect(result).toStrictEqual([null, 401200]);
        bcryptSpy.mockRestore();
    });
    
    test("Handle client token 404100", async () => {
        const client_id = "username";
        const client_secret = "password";
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockResolvedValue([]),
        };
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleClientToken(
          client_id,
          client_secret
        );
    
        expect(result).toStrictEqual([null, 404100]);
    });
    
    test("Handle client token function", async () => {
        const client_id = "username";
        const client_secret = "password";
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest
            .fn()
            .mockResolvedValue([
              { id: 1, roles: "role", client_secret: "x|.|password" },
            ]),
        };
    
        const decipherSpy = jest
          .spyOn(crypto, "createDecipheriv")
          .mockImplementation(() => {
            return {
              update: jest.fn().mockReturnValue("password"),
              final: jest.fn().mockReturnValue(""),
            };
          });
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleClientToken(
          client_id,
          client_secret
        );
    
        expect(decipherSpy).toHaveBeenCalled();
        expect(result[1]).toBe(null);
    });
    
    test("Handle client token 401100", async () => {
        const client_id = "username";
        const client_secret = "password";
        const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
          return false;
        });
        const bufferSpy = jest.spyOn(Buffer, "from");
        const decipherSpy = jest
          .spyOn(crypto, "createDecipheriv")
          .mockImplementation(() => {
            return {
              update: jest.fn().mockReturnValue("u"),
              final: jest.fn().mockReturnValue("U"),
            };
          });
    
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          join: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnThis(),
          andWhere: jest
            .fn()
            .mockResolvedValue([{ id: 1, roles: "role", client_secret: "x|.|y" }]),
        };
    
        const controllers = authControllers(knex, "secret");
        const result = await controllers.handleClientToken(
          client_id,
          client_secret
        );
    
        expect(result).toStrictEqual([null, 401100]);
        expect(bufferSpy).toHaveBeenCalled();
        expect(decipherSpy).toHaveBeenCalled();
    
        bcryptSpy.mockRestore();
        bufferSpy.mockRestore();
        decipherSpy.mockRestore();
    });

    test("Revoke Token Works", async () => {
      const req = {
        body: {
          revoke: false,
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
        update: jest.fn().mockReturnThis(),
        where: jest.fn(),
      };
  
      const controllers = authControllers(knex, "secret");
      await controllers.revokeToken(req, res);
  
      expect(res.status).toHaveBeenCalledWith(201);
  
      expect(knex.update).toHaveBeenCalledWith({ revoked: false });
    });

    test("Revoke Token fails", async () => {
      const req = {
        body: {
          revoke: false,
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
        update: jest.fn().mockReturnThis(),
        where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      };
  
      const controllers = authControllers(knex, "secret");
  
      controllers.handleError500 = jest.fn();
      controllers.callNextOrResOnError = jest.fn();
  
      await controllers.revokeToken(req, res);
  
      expect(controllers.handleError500).toHaveBeenCalled();
      expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
});