const authControllers = require("../../src/helpers/routes/controllers");

describe('Controllers - permission', () => {
    test("Create permission", async () => {
        const mockedReq = {
          body: {
            allowed: "allowed",
            applicationResource_id: 1,
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
    
        await controllers.createPermission(mockedReq, mockRes);
    
        expect(mockRes.status).toHaveBeenCalledWith(201);
        expect(mockRes.json).toHaveBeenCalled();
        expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Permissions");
    });
    
    test("Create permission error", async () => {
        const mockedReq = {
          body: {
            allowed: "allowed",
            applicationResource_id: 1,
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
    
        await controllers.createPermission(mockedReq, mockRes, jest.fn());
    
        expect(controllers.handleError500).toHaveBeenCalled();
        expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    });
});