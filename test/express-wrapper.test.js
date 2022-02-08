const ExpressWrapper = require("../src/helpers/ExpressWrapper.js");

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

const expressRouterMock = () => {
  const express = { getMemory: {} };

  express.get = jest.fn();

  express.post = jest.fn();

  express.put = jest.fn();

  express.delete = jest.fn();

  return express;
};

describe("Express Wrapper and his functions work as required", () => {
  const expressWrapper = new ExpressWrapper();

  test("Correct create secure POST", () => {
    const fullMock = expressMock();
    const mockGuard = () => {
      return () => {
        return "mocked";
      };
    };
    fullMock.obPost = expressWrapper.createSecurePost(fullMock, mockGuard);

    fullMock.obPost("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("POST" + "||" + "somePath")).toBe("allowed");
    expect(fullMock.post).toHaveBeenCalled();
  });

  test("Correct create secure POST for router", () => {
    const fullMock = expressMock();

    const router = expressRouterMock();

    const mockGuard = () => {
      return () => {
        return "mocked";
      };
    };

    router.obPost = expressWrapper.createSecurePostRouter(
      fullMock,
      router,
      "baseResource/",
      mockGuard
    );

    router.obPost("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("POST" + "||" + "baseResource/somePath")).toBe(
      "allowed"
    );
    expect(router.post).toHaveBeenCalled();
  });

  test("Correct create secure GET", () => {
    const fullMock = expressMock();
    function mockGuard() {
      return () => {
        return "mocked";
      };
    }
    fullMock.obGet = expressWrapper.createSecureGet(fullMock, mockGuard);

    fullMock.obGet("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get).toHaveBeenCalled();
    expect(fullMock.get("GET" + "||" + "somePath")).toBe("allowed");
  });

  test("Correct create secure GET for router", () => {
    const fullMock = expressMock();

    const router = expressRouterMock();

    const mockGuard = () => {
      return () => {
        return "mocked";
      };
    };

    router.obGet = expressWrapper.createSecureGetRouter(
      fullMock,
      router,
      "baseResource/",
      mockGuard
    );

    router.obGet("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("GET" + "||" + "baseResource/somePath")).toBe(
      "allowed"
    );
    expect(router.get).toHaveBeenCalled();
  });

  test("Correct create secure PUT", () => {
    const fullMock = expressMock();
    function mockGuard() {
      return () => {
        return "mocked";
      };
    }
    fullMock.obPut = expressWrapper.createSecurePut(fullMock, mockGuard);

    fullMock.obPut("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("PUT" + "||" + "somePath")).toBe("allowed");
    expect(fullMock.put).toHaveBeenCalled();
  });

  test("Correct create secure PUT for router", () => {
    const fullMock = expressMock();

    const router = expressRouterMock();

    const mockGuard = () => {
      return () => {
        return "mocked";
      };
    };

    router.obPut = expressWrapper.createSecurePutRouter(
      fullMock,
      router,
      "baseResource/",
      mockGuard
    );

    router.obPut("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("PUT" + "||" + "baseResource/somePath")).toBe(
      "allowed"
    );
    expect(router.put).toHaveBeenCalled();
  });

  test("Correct create secure DELETE", () => {
    const fullMock = expressMock();
    function mockGuard() {
      return () => {
        return "mocked";
      };
    }
    fullMock.obPut = expressWrapper.createSecureDelete(fullMock, mockGuard);

    fullMock.obPut("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("DELETE" + "||" + "somePath")).toBe("allowed");
    expect(fullMock.delete).toHaveBeenCalled();
  });

  test("Correct create secure DELETE for router", () => {
    const fullMock = expressMock();

    const router = expressRouterMock();

    const mockGuard = () => {
      return () => {
        return "mocked";
      };
    };

    router.obPut = expressWrapper.createSecureDeleteRouter(
      fullMock,
      router,
      "baseResource/",
      mockGuard
    );

    router.obPut("somePath", "allowed", () => {
      return "handle";
    });

    expect(fullMock.get("DELETE" + "||" + "baseResource/somePath")).toBe(
      "allowed"
    );
    expect(router.delete).toHaveBeenCalled();
  });
});
