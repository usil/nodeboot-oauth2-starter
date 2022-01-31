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
        console.log(userObject);
        if (!usersBaseArray[index].roleDeleted) {
          userObject.roles.push({
            id: usersBaseArray[index].roleId,
            identifier: usersBaseArray[index].roleIdentifier,
            parts: [
              {
                id: usersBaseArray[index].partId,
                applicationPartName: usersBaseArray[index].applicationPart,
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
            parts: [
              {
                id: usersBaseArray[index].partId,
                applicationPartName: usersBaseArray[index].applicationPart,
                allowed: [usersBaseArray[index].allowed],
              },
            ],
          });
        } else {
          const indexOption = newArray[lastIndex].roles[
            indexRole
          ].parts.findIndex(
            (o) =>
              o.applicationPartName === usersBaseArray[index].applicationPart
          );
          if (indexOption === -1) {
            newArray[lastIndex].roles[indexRole].parts.push({
              id: usersBaseArray[index].partId,
              applicationPartName: usersBaseArray[index].applicationPart,
              allowed: [usersBaseArray[index].allowed],
            });
          } else {
            newArray[lastIndex].roles[indexRole].parts[
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
          parts: [
            {
              id: rolesBaseArray[index].partId,
              applicationPartName: rolesBaseArray[index].applicationPart,
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
        const indexOption = newArray[lastIndex].parts.findIndex(
          (o) => o.applicationPartName === rolesBaseArray[index].applicationPart
        );
        if (indexOption === -1) {
          newArray[lastIndex].parts.push({
            id: rolesBaseArray[index].partId,
            applicationPartName: rolesBaseArray[index].applicationPart,
            allowed: [
              {
                allowed: rolesBaseArray[index].allowed,
                id: rolesBaseArray[index].optionId,
              },
            ],
          });
        } else {
          newArray[lastIndex].parts[indexOption].allowed.push({
            allowed: rolesBaseArray[index].allowed,
            id: rolesBaseArray[index].optionId,
          });
        }
      }
    }
    return newArray;
  };
  helpersObj.parsePartSearch = (partBaseArray) => {
    const newArray = [];
    for (let index = 0; index < partBaseArray.length; index++) {
      if (
        (partBaseArray[index - 1] &&
          partBaseArray[index].applicationPartName !==
            partBaseArray[index - 1].applicationPartName) ||
        index === 0
      ) {
        const roleObject = {
          id: partBaseArray[index].partId,
          applicationPartName: partBaseArray[index].applicationPartName,
          allowed: [
            {
              allowed: partBaseArray[index].allowed,
              id: partBaseArray[index].optionId,
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const indexOption = newArray.findIndex(
          (o) =>
            o.applicationPartName === partBaseArray[index].applicationPartName
        );
        newArray[indexOption].allowed.push({
          allowed: partBaseArray[index].allowed,
          id: partBaseArray[index].optionId,
        });
      }
    }
    return newArray;
  };

  return helpersObj;
};

module.exports = generalHelpers;
