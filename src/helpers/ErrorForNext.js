class ErrorForNext {
  constructor(message = "", statusCode = 500) {
    this.message = message;
    this.statusCode = statusCode;
  }

  setOriginalError(originalError) {
    this.originalError = originalError;
    return this;
  }

  setErrorCode(errorCode = 500) {
    this.errorCode = errorCode;
    return this;
  }

  setOnFunction(onFunction = "") {
    this.onFunction = onFunction;
    return this;
  }

  setOnLibrary(onLibrary = "") {
    this.onLibrary = onLibrary;
    return this;
  }

  setOnFile(onFile = "") {
    this.onFile = onFile;
    return this;
  }

  setLogMessage(logMessage = "") {
    this.logMessage = logMessage;
    return this;
  }

  setErrorObject(errorObject = {}) {
    this.errorObject = errorObject;
    return this;
  }

  toJson() {
    return {
      message: this.message,
      statusCode: this.statusCode,
      errorCode: this.errorCode,
      onFunction: this.onFunction,
      onLibrary: this.onLibrary,
      onFile: this.onFile,
      logMessage: this.logMessage,
      errorObject: this.errorObject,
      originalError: this.originalError,
    };
  }
}

module.exports = ErrorForNext;
