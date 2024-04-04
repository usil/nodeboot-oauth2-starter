const ErrorForNext = require("./ErrorForNext.js");

const generalHelpers = () => {
  const helpersObj = {};
  helpersObj.joinSearch = (baseSearch, differentiator, ...similarFields) => {
    const newArray = [];
    for (let index = 0; index < baseSearch.length; index++) {
      if (
        index === 0 ||
        baseSearch[index][differentiator] !==
          baseSearch[index - 1][differentiator]
      ) {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          baseSearch[index][similarField] = [temporalFieldValue];
        }
        newArray.push(baseSearch[index]);
      } else {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          newArray[newArray.length - 1][similarField].push(temporalFieldValue);
        }
      }
    }
    return newArray;
  };
  helpersObj.parsePathNoRoute = (path) => {
    let parsedPath = path;
    if (parsedPath.slice(parsedPath.length - 1) === "/" && parsedPath !== "/") {
      parsedPath = parsedPath.slice(0, -1);
    }
    return parsedPath;
  };
  helpersObj.parsePathWithRoute = (path) => {
    if (path === "/") {
      return "";
    }
    if (path.slice(path.length - 1) === "/") {
      return path.slice(0, -1);
    }
    return path;
  };
  helpersObj.handleError400 = (
    res,
    next,
    externalErrorHandle,
    message,
    errorCode,
    code = 400
  ) => {
    if (!externalErrorHandle) {
      res.status(code).json({
        code: errorCode,
        message,
      });
      return;
    }
    const errorJson = new ErrorForNext(message, code)
      .setErrorCode(errorCode)
      .setOnFile("genera-helpers.js")
      .setOnLibrary("nodeboot-oauth2-starter")
      .setLogMessage(message)
      .toJson();
    next(errorJson);
  };

  helpersObj.validateBody = (
    validationPermissions,
    externalErrorHandle = true
  ) => {
    const validateObj = {};
    validateObj.validate = (req, res, next) => {
      for (const parameter in validationPermissions) {
        if (
          (validationPermissions[parameter].required === true ||
            validationPermissions[parameter].required === undefined) &&
          req.body[parameter] === undefined
        ) {
          return helpersObj.handleError400(
            res,
            next,
            externalErrorHandle,
            `Invalid body; ${parameter} is required`,
            400001
          );
        }

        switch (validationPermissions[parameter].type) {
          case "array":
            if (!Array.isArray(req.body[parameter])) {
              return helpersObj.handleError400(
                res,
                next,
                externalErrorHandle,
                `Invalid body; ${parameter} is not an array`,
                400002
              );
            }
            break;
          case "string":
            if (
              Object.prototype.toString.call(req.body[parameter]) !==
              "[object String]"
            ) {
              return helpersObj.handleError400(
                res,
                next,
                externalErrorHandle,
                `Invalid body; ${parameter} is not an string`,
                400003
              );
            }
            break;
          case "number":
            if (isNaN(req.body[parameter])) {
              return helpersObj.handleError400(
                res,
                next,
                externalErrorHandle,
                `Invalid body; ${parameter} is not a number`,
                400004
              );
            }
            break;
          case "object":
            if (typeof req.body[parameter] !== "object") {
              return helpersObj.handleError400(
                res,
                next,
                externalErrorHandle,
                `Invalid body; ${parameter} is not an object`,
                400005
              );
            }
            break;
          case "boolean":
            if (
              req.body[parameter] !== "true" &&
              req.body[parameter] !== "false" &&
              req.body[parameter] !== false &&
              req.body[parameter] !== true
            ) {
              return helpersObj.handleError400(
                res,
                next,
                externalErrorHandle,
                `Invalid body; ${parameter} is not a boolean`,
                400006
              );
            }
            break;
          default:
            break;
        }
      }

      next();
    };
    return validateObj;
  };
  helpersObj.parseSubjectSearch = (usersBaseArray, subjectType = "user") => {
    const newArray = [];
    const userNameOrIdentifier =
      subjectType === "user" ? "username" : "identifier";
    for (let index = 0; index < usersBaseArray.length; index++) {
      if (
        (usersBaseArray[index - 1] &&
          usersBaseArray[index].id !== usersBaseArray[index - 1].id) ||
        index === 0
      ) {
        const userObject = {
          id: usersBaseArray[index].id,
          description: usersBaseArray[index].description,
          subjectId: usersBaseArray[index].subjectId,
          name: usersBaseArray[index].name,
          [userNameOrIdentifier]: usersBaseArray[index][userNameOrIdentifier],
          roles: [],
        };
        if (subjectType === "client") {
          userObject["client_id"] = usersBaseArray[index].client_id;
          userObject["hasLongLiveToken"] = usersBaseArray[index].access_token
            ? true
            : false;
          userObject["revoked"] =
            usersBaseArray[index].revoked === 0 ? false : true;
        }
        if (!usersBaseArray[index].roleDeleted) {
          userObject.roles.push({
            id: usersBaseArray[index].roleId,
            identifier: usersBaseArray[index].roleIdentifier,
            resources: [
              {
                id: usersBaseArray[index].resourceId,
                applicationResourceName:
                  usersBaseArray[index].applicationResource,
                allowed: [usersBaseArray[index].allowed],
              },
            ],
          });
        }
        newArray.push(userObject);
      } else if (!usersBaseArray[index].roleDeleted) {
        const lastIndex = newArray.length - 1;
        const indexRole = newArray[lastIndex].roles.findIndex(
          (r) => r.id === usersBaseArray[index].roleId
        );
        if (indexRole === -1) {
          newArray[lastIndex].roles.push({
            id: usersBaseArray[index].roleId,
            identifier: usersBaseArray[index].roleIdentifier,
            resources: [
              {
                id: usersBaseArray[index].resourceId,
                applicationResourceName:
                  usersBaseArray[index].applicationResource,
                allowed: [usersBaseArray[index].allowed],
              },
            ],
          });
        } else {
          const indexPermission = newArray[lastIndex].roles[
            indexRole
          ].resources.findIndex(
            (o) =>
              o.applicationResourceName ===
              usersBaseArray[index].applicationResource
          );
          if (indexPermission === -1) {
            newArray[lastIndex].roles[indexRole].resources.push({
              id: usersBaseArray[index].resourceId,
              applicationResourceName:
                usersBaseArray[index].applicationResource,
              allowed: [usersBaseArray[index].allowed],
            });
          } else {
            newArray[lastIndex].roles[indexRole].resources[
              indexPermission
            ].allowed.push(usersBaseArray[index].allowed);
          }
        }
      }
    }
    return newArray;
  };
  helpersObj.parseRoleSearch = (rolesBaseArray) => {
    const newArray = [];
    for (let index = 0; index < rolesBaseArray.length; index++) {
      if (
        (rolesBaseArray[index - 1] &&
          rolesBaseArray[index].id !== rolesBaseArray[index - 1].id) ||
        index === 0
      ) {
        const roleObject = {
          id: rolesBaseArray[index].id,
          identifier: rolesBaseArray[index].identifier,
          resources: [
            {
              id: rolesBaseArray[index].resourceId,
              applicationResourceName:
                rolesBaseArray[index].applicationResource,
              allowed: [
                {
                  allowed: rolesBaseArray[index].allowed,
                  id: rolesBaseArray[index].permissionId,
                },
              ],
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const lastIndex = newArray.length - 1;
        const indexPermission = newArray[lastIndex].resources.findIndex(
          (o) =>
            o.applicationResourceName ===
            rolesBaseArray[index].applicationResource
        );
        if (indexPermission === -1) {
          newArray[lastIndex].resources.push({
            id: rolesBaseArray[index].resourceId,
            applicationResourceName: rolesBaseArray[index].applicationResource,
            allowed: [
              {
                allowed: rolesBaseArray[index].allowed,
                id: rolesBaseArray[index].permissionId,
              },
            ],
          });
        } else {
          newArray[lastIndex].resources[indexPermission].allowed.push({
            allowed: rolesBaseArray[index].allowed,
            id: rolesBaseArray[index].permissionId,
          });
        }
      }
    }
    return newArray;
  };
  helpersObj.parseResourceSearch = (resourceBaseArray) => {
    const newArray = [];
    for (let index = 0; index < resourceBaseArray.length; index++) {
      if (
        (resourceBaseArray[index - 1] &&
          resourceBaseArray[index].applicationResourceName !==
            resourceBaseArray[index - 1].applicationResourceName) ||
        index === 0
      ) {
        const roleObject = {
          id: resourceBaseArray[index].resourceId,
          applicationResourceName:
            resourceBaseArray[index].applicationResourceName,
          allowed: [
            {
              allowed: resourceBaseArray[index].allowed,
              id: resourceBaseArray[index].permissionId,
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const indexPermissions = newArray.findIndex(
          (o) =>
            o.applicationResourceName ===
            resourceBaseArray[index].applicationResourceName
        );
        newArray[indexPermissions].allowed.push({
          allowed: resourceBaseArray[index].allowed,
          id: resourceBaseArray[index].permissionId,
        });
      }
    }
    return newArray;
  };

  helpersObj.isSubjectLocked = (subjectLoginDetails, subjectId, coldDownInMinutes) => {

    if(typeof subjectLoginDetails[subjectId] === 'undefined') return false;
    
    if(subjectLoginDetails[subjectId].isLocked){
      //if more than coldDownInMinutes have passed, it will be unlocked
      var minutes = getDifferenceInMinutes(subjectLoginDetails[subjectId].startLockingDateMillis)
      console.log(`coldDownInMinutes ${coldDownInMinutes} minutes: ${minutes}`)
      if(minutes>coldDownInMinutes){
        subjectLoginDetails[subjectId].failedAttemptCount = 0;
        subjectLoginDetails[subjectId].isLocked = false;
        delete subjectLoginDetails[subjectId].startLockingDateMillis;
      }
      //finally return true but in the next attempt, account is unlocked
      return true;
    }else{
      return false;
    }
  };

  helpersObj.initializeSubjectLoginDetails = (subjectLoginDetails, subjectId) => {
    if(typeof subjectLoginDetails[subjectId] === 'undefined'){
      subjectLoginDetails[subjectId] = {};
    }
  };   

  helpersObj.increaseIncorrectPasswordCount = (subjectLoginDetails, subjectId, maxFailedLoginAttemptCount) => {

    if(typeof subjectLoginDetails[subjectId] === 'undefined'){
      subjectLoginDetails[subjectId] = {};
    }

    subjectLoginDetails[subjectId].failedAttemptCount = 
      new Number(subjectLoginDetails[subjectId].failedAttemptCount||0)+1;
    
    if(subjectLoginDetails[subjectId].failedAttemptCount > maxFailedLoginAttemptCount){
      subjectLoginDetails[subjectId].isLocked = true;
      subjectLoginDetails[subjectId].startLockingDateMillis =  new Date().getTime();
    }
  };  

  getDifferenceInMinutes = (startTimeInMillis)=>{
    var endTime = new Date();
    var difference = endTime.getTime() - startTimeInMillis; 
    return Math.round(difference / 60000);
  }

  return helpersObj;
};

module.exports = generalHelpers;