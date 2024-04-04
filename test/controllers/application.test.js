const authControllers = require("../../src/helpers/routes/controllers");

describe('Controllers - application', () => {
    test("Create application", async () => {
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
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnValue([]),
          insert: jest.fn().mockReturnValue([1]),
        };
    
        const nextMock = jest.fn();
    
        const controllers = authControllers(knexMock, "secret");
    
        await controllers.createApplication(mockedReq, mockRes, nextMock);
    
        expect(mockRes.status).toHaveBeenCalledWith(201);
        expect(mockRes.json).toHaveBeenCalledWith({
          code: 200001,
          message: "Application added",
          content: { applicationId: 1 },
        });
        expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Applications");
        expect(knexMock.select).toHaveBeenCalled();
        expect(knexMock.where).toHaveBeenCalledWith("identifier", "identifier");
    });
    
    test("Create application, duplicated", async () => {
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
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnValue([{ id: 1 }]),
          insert: jest.fn().mockReturnValue([1]),
        };
    
        const nextMock = jest.fn();
    
        const controllers = authControllers(knexMock, "secret");
    
        controllers.handleNotUniqueError409 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
    
        await controllers.createApplication(mockedReq, mockRes, nextMock);
    
        expect(controllers.handleNotUniqueError409).toHaveBeenCalledWith(
          "identifier",
          409104,
          "createApplication"
        );
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
    
    test("Create application error", async () => {
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
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockReturnValue([]),
          insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
        };
    
        const nextMock = jest.fn();
    
        const controllers = authControllers(knexMock, "secret");
    
        controllers.handleError500 = jest.fn();
    
        controllers.callNextOrResOnError = jest.fn();
    
        await controllers.createApplication(mockedReq, mockRes, nextMock);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });

    test("Create application resource", async () => {
        const mockedReq = {
          body: {
            resourceIdentifier: "identifier",
            applications_id: 1,
          },
        };
    
        const mockRes = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knexMock = {
          table: jest.fn().mockReturnThis(),
          insert: jest.fn().mockReturnValue([1]),
        };
    
        const controllers = authControllers(knexMock, "secret");
    
        await controllers.createApplicationResource(mockedReq, mockRes);
    
        expect(mockRes.status).toHaveBeenCalledWith(201);
        expect(mockRes.json).toHaveBeenCalled();
        expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_ApplicationResource");
    });
    
    test("Create application resource error", async () => {
        const mockedReq = {
          body: {
            resourceIdentifier: "identifier",
            applications_id: 1,
          },
        };
    
        const mockRes = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
        };
    
        const knexMock = {
          table: jest.fn().mockReturnThis(),
          insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
        };
    
        const controllers = authControllers(knexMock, "secret");
    
        controllers.handleError500 = jest.fn();
    
        controllers.callNextOrResOnError = jest.fn();
    
        await controllers.createApplicationResource(mockedReq, mockRes, jest.fn());
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });

    test("Select applications", async () => {
        const req = {};
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockResolvedValue([1]),
        };
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockResolvedValue([1]),
        };
        const controllers = authControllers(knex, "secret");
        await controllers.selectApplications(req, res);
    
        expect(knex.table).toHaveBeenCalledWith("OAUTH2_Applications");
        expect(knex.select).toHaveBeenCalled();
    
        expect(res.status).toHaveBeenCalledWith(200);
    });

    test("Select applications fails", async () => {
        const req = {};
        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockResolvedValue([1]),
        };
        const knex = {
          table: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
        };
        const controllers = authControllers(knex, "secret");
        controllers.handleError500 = jest.fn();
        controllers.callNextOrResOnError = jest.fn();
        await controllers.selectApplications(req, res);
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
});