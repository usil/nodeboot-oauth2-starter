const generalHelpers = () => {
  const helpersObj = {};
  helpersObj.joinSearch = (baseSearch, differentiator, ...similarFields) => {
    const newArray = [];
    for (let index = 0; index < baseSearch.length; index++) {
      if (index === 0) {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          baseSearch[index][similarField] = [temporalFieldValue];
        }
        newArray.push(baseSearch[index]);
      } else if (
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
  helpersObj.compareKeys = (a, b) => {
    var aKeys = Object.keys(a).sort();
    var bKeys = Object.keys(b).sort();
    return JSON.stringify(aKeys) === JSON.stringify(bKeys);
  };
  helpersObj.validateBody = (validationOptions) => {
    const validateObj = {};
    validateObj.validate = (req, res, next) => {
      if (!helpersObj.compareKeys(req.body, validationOptions))
        return res.status(400).json({ code: 400000, message: "Invalid body" });

      for (const option in validationOptions) {
        switch (validationOptions[option].type) {
          case "array":
            if (!Array.isArray(req.body[option])) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an array`,
              });
            }
            break;
          case "string":
            if (
              !(
                Object.prototype.toString.call(req.body[option]) ==
                "[object String]"
              )
            ) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an string`,
              });
            }
            break;
          case "number":
            if (isNaN(req.body[option])) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not a number`,
              });
            }
            break;
          case "object":
            if (!(typeof req.body[option] === "object")) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an object`,
              });
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
          const indexOption = newArray[lastIndex].roles[
            indexRole
          ].resources.findIndex(
            (o) =>
              o.applicationResourceName ===
              usersBaseArray[index].applicationResource
          );
          if (indexOption === -1) {
            newArray[lastIndex].roles[indexRole].resources.push({
              id: usersBaseArray[index].resourceId,
              applicationResourceName:
                usersBaseArray[index].applicationResource,
              allowed: [usersBaseArray[index].allowed],
            });
          } else {
            newArray[lastIndex].roles[indexRole].resources[
              indexOption
            ].allowed.push(usersBaseArray[index].allowed);
          }
        }
      }
    }
    console.log(newArray);
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
                  id: rolesBaseArray[index].optionId,
                },
              ],
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const lastIndex = newArray.length - 1;
        const indexOption = newArray[lastIndex].resources.findIndex(
          (o) =>
            o.applicationResourceName ===
            rolesBaseArray[index].applicationResource
        );
        if (indexOption === -1) {
          newArray[lastIndex].resources.push({
            id: rolesBaseArray[index].resourceId,
            applicationResourceName: rolesBaseArray[index].applicationResource,
            allowed: [
              {
                allowed: rolesBaseArray[index].allowed,
                id: rolesBaseArray[index].optionId,
              },
            ],
          });
        } else {
          newArray[lastIndex].resources[indexOption].allowed.push({
            allowed: rolesBaseArray[index].allowed,
            id: rolesBaseArray[index].optionId,
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
              id: resourceBaseArray[index].optionId,
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const indexOption = newArray.findIndex(
          (o) =>
            o.applicationResourceName ===
            resourceBaseArray[index].applicationResourceName
        );
        newArray[indexOption].allowed.push({
          allowed: resourceBaseArray[index].allowed,
          id: resourceBaseArray[index].optionId,
        });
      }
    }
    return newArray;
  };

  return helpersObj;
};

module.exports = generalHelpers;
